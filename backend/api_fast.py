import csv
import io
import json
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, Query, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_

from Database import init_db, get_session
from Models import Vulnerability, Alert, SyncLog

try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:
    BackgroundScheduler = None
    print("⚠️  apscheduler non installé — le rafraîchissement automatique quotidien sera désactivé.")
    print("    Installez-le avec : pip install apscheduler")

app = FastAPI(title="VulnWatch API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===== DÉMARRAGE =====

@app.on_event("startup")
def on_startup():
    init_db()
    print("✅ Base de données initialisée")
    if BackgroundScheduler:
        scheduler = BackgroundScheduler()
        scheduler.add_job(_scheduled_collection, "cron", hour=2, minute=0)
        scheduler.start()
        print("⏰ Rafraîchissement automatique programmé tous les jours à 2h00.")


def _scheduled_collection():
    print(f"🌙 [{datetime.now()}] Lancement de la collecte automatique quotidienne...")
    try:
        from collect_data import run_collection
        run_collection(trigger="scheduled")
    except Exception as e:
        print(f"❌ Erreur pendant la collecte automatique: {e}")


# ===== HELPERS =====

def _vuln_to_dict(v: Vulnerability) -> dict:
    return {
        "id": v.id,
        "vendor": v.vendor,
        "product": v.product,
        "products": json.loads(v.products) if v.products else [],
        "description": v.description,
        "cvss_score": v.cvss_score,
        "severity": v.severity,
        "unscored": v.unscored,
        "published_date": v.published_date,
        "patch_available": v.patch_available,
        "kev_status": v.kev_status,
        "versions": v.versions,
        "references": json.loads(v.references) if v.references else [],
        "source": v.source,
    }


def _apply_filters(
    query,
    vendor: Optional[str],
    product: Optional[str],
    severity: Optional[str],
    kev: Optional[bool],
    min_score: Optional[float],
    max_score: Optional[float],
    search: Optional[str],
):
    if vendor and vendor != "all":
        query = query.filter(Vulnerability.vendor == vendor)
    if product and product != "all":
        query = query.filter(Vulnerability.product == product)
    if severity and severity != "all":
        query = query.filter(Vulnerability.severity == severity.upper())
    if kev is not None:
        query = query.filter(Vulnerability.kev_status == kev)
    if min_score is not None:
        query = query.filter(Vulnerability.cvss_score >= min_score)
    if max_score is not None:
        query = query.filter(Vulnerability.cvss_score <= max_score)
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Vulnerability.id.ilike(like),
                Vulnerability.vendor.ilike(like),
                Vulnerability.product.ilike(like),
                Vulnerability.description.ilike(like),
            )
        )
    return query


# ===== ROUTES =====

@app.get("/")
def home():
    return {
        "name": "VulnWatch API",
        "version": "2.0.0",
        "status": "running",
        "endpoints": {
            "/api/vulnerabilities": "Liste filtrable des vulnérabilités",
            "/api/vulnerabilities/{id}": "Détail d'une CVE",
            "/api/stats": "Statistiques",
            "/api/vendors": "Liste des vendeurs",
            "/api/products": "Liste des produits",
            "/api/alerts": "Alertes générées",
            "/api/export/csv": "Export CSV",
            "/api/export/pdf": "Export PDF",
            "/api/health": "Statut de l'API",
        },
    }


@app.get("/api/health")
def health(session: Session = Depends(get_session)):
    try:
        count = session.query(Vulnerability).count()
        return {"status": "healthy", "database": "connected", "vulnerabilities_count": count}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}


@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    kev: Optional[bool] = Query(None),
    min_score: Optional[float] = Query(None, description="Score CVSS minimum (0-10)"),
    max_score: Optional[float] = Query(None, description="Score CVSS maximum (0-10)"),
    search: Optional[str] = Query(None),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
    session: Session = Depends(get_session),
):
    query = session.query(Vulnerability)
    query = _apply_filters(query, vendor, product, severity, kev, min_score, max_score, search)
    total = query.count()
    items = query.order_by(Vulnerability.published_date.desc()).offset(offset).limit(limit).all()

    return {
        "generated_at": datetime.now().isoformat(),
        "total": total,
        "vulnerabilities": [_vuln_to_dict(v) for v in items],
    }


@app.get("/api/vulnerabilities/{cve_id}")
def get_vulnerability_detail(cve_id: str, session: Session = Depends(get_session)):
    v = session.get(Vulnerability, cve_id)
    if not v:
        raise HTTPException(status_code=404, detail=f"CVE {cve_id} not found")
    return _vuln_to_dict(v)


@app.get("/api/stats")
def get_stats(session: Session = Depends(get_session)):
    vulnerabilities = session.query(Vulnerability).all()
    if not vulnerabilities:
        return {
            "total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
            "kev_count": 0, "patch_available": 0, "by_vendor": {}, "last_30_days": 0,
        }

    stats = {
        "total": len(vulnerabilities),
        "critical": 0, "high": 0, "medium": 0, "low": 0,
        "kev_count": 0, "patch_available": 0,
        "by_vendor": {}, "last_30_days": 0,
    }
    thirty_days_ago = datetime.now().timestamp() - 30 * 86400

    for v in vulnerabilities:
        key = v.severity.lower()
        stats[key] = stats.get(key, 0) + 1
        if v.kev_status:
            stats["kev_count"] += 1
        if v.patch_available:
            stats["patch_available"] += 1
        stats["by_vendor"][v.vendor] = stats["by_vendor"].get(v.vendor, 0) + 1
        try:
            pub_ts = datetime.fromisoformat(v.published_date.replace("Z", "+00:00")).timestamp()
            if pub_ts >= thirty_days_ago:
                stats["last_30_days"] += 1
        except Exception:
            pass

    return stats


@app.get("/api/vendors")
def get_vendors(session: Session = Depends(get_session)):
    rows = session.query(Vulnerability.vendor).distinct().all()
    return {"vendors": sorted(r[0] for r in rows if r[0])}


@app.get("/api/products")
def get_products(vendor: Optional[str] = Query(None), session: Session = Depends(get_session)):
    query = session.query(Vulnerability.product).distinct()
    if vendor and vendor != "all":
        query = query.filter(Vulnerability.vendor == vendor)
    rows = query.all()
    return {"products": sorted(set(r[0] for r in rows if r[0]))}


@app.get("/api/export/csv")
def export_csv(
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    kev: Optional[bool] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    search: Optional[str] = Query(None),
    session: Session = Depends(get_session),
):
    query = session.query(Vulnerability)
    query = _apply_filters(query, vendor, product, severity, kev, min_score, max_score, search)
    items = query.order_by(Vulnerability.published_date.desc()).all()

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "CVE ID", "Vendeur", "Produit", "Score CVSS", "Sévérité",
        "Date de publication", "Correctif disponible", "Exploitée (KEV)",
        "Versions affectées", "Description", "Source",
    ])
    for v in items:
        writer.writerow([
            v.id, v.vendor, v.product, v.cvss_score, v.severity,
            v.published_date, "Oui" if v.patch_available else "Non",
            "Oui" if v.kev_status else "Non", v.versions, v.description, v.source,
        ])

    buffer.seek(0)
    filename = f"vulnwatch_export_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ===== ROUTE PDF AJOUTÉE =====

@app.get("/api/export/pdf")
def export_pdf(
    vendor: Optional[str] = Query(None),
    product: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    kev: Optional[bool] = Query(None),
    min_score: Optional[float] = Query(None),
    max_score: Optional[float] = Query(None),
    session: Session = Depends(get_session),
):

    try:
        from reportlab.lib.pagesizes import letter, landscape
        from reportlab.pdfgen import canvas
        from reportlab.lib import colors
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
    except ImportError:
        raise HTTPException(
            status_code=500, 
            detail="reportlab non installé. Installez avec: pip install reportlab"
        )
    
    query = session.query(Vulnerability)
    query = _apply_filters(query, vendor, product, severity, kev, min_score, max_score, None)
    items = query.order_by(Vulnerability.published_date.desc()).all()
    
    if not items:
        raise HTTPException(status_code=404, detail="Aucune donnée à exporter")
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=landscape(letter))
    elements = []
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=16,
        alignment=1,  # Center
        spaceAfter=20
    )
    
    # Titre
    elements.append(Paragraph("VulnWatch - Rapport des vulnérabilités", title_style))
    elements.append(Paragraph(f"Généré le: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles['Normal']))
    elements.append(Paragraph(f"Total: {len(items)} vulnérabilités", styles['Normal']))
    elements.append(Spacer(1, 20))
    
    # Tableau
    data = [["CVE ID", "Vendeur", "Produit", "Score", "Sévérité", "KEV", "Date"]]
    
    for v in items[:100]:
        data.append([
            v.id or "",
            v.vendor or "",
            v.product or "",
            str(v.cvss_score or ""),
            v.severity or "",
            "✅" if v.kev_status else "",
            v.published_date[:10] if v.published_date else ""
        ])
    
    table = Table(data, colWidths=[90, 90, 90, 50, 60, 40, 80])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('FONTSIZE', (0, 1), (-1, -1), 8),
    ]))
    
    elements.append(table)
    doc.build(elements)
    buffer.seek(0)
    
    filename = f"vulnwatch_export_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.get("/api/alerts")
def get_alerts(
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(50, le=200),
    session: Session = Depends(get_session),
):
    query = session.query(Alert)
    if acknowledged is not None:
        query = query.filter(Alert.acknowledged == acknowledged)
    items = query.order_by(Alert.created_at.desc()).limit(limit).all()
    unread_count = session.query(Alert).filter(Alert.acknowledged == False).count()

    return {
        "unread_count": unread_count,
        "alerts": [
            {
                "id": a.id,
                "cve_id": a.cve_id,
                "vendor": a.vendor,
                "reason": a.reason,
                "message": a.message,
                "created_at": a.created_at.isoformat(),
                "acknowledged": a.acknowledged,
            }
            for a in items
        ],
    }


@app.post("/api/alerts/{alert_id}/ack")
def acknowledge_alert(alert_id: int, session: Session = Depends(get_session)):
    alert = session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.acknowledged = True
    session.commit()
    return {"status": "ok", "id": alert_id}


@app.post("/api/alerts/ack_all")
def acknowledge_all_alerts(session: Session = Depends(get_session)):
    count = (
        session.query(Alert)
        .filter(Alert.acknowledged == False)
        .update({"acknowledged": True})
    )
    session.commit()
    return {"status": "ok", "acknowledged_count": count}


@app.post("/api/sync")
def trigger_manual_sync():
    try:
        from collect_data import run_collection
        run_collection(trigger="api")
        return {"status": "ok", "message": "Collecte terminée"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/sync-logs")
def get_sync_logs(limit: int = Query(20, le=100), session: Session = Depends(get_session)):
    """Historique des synchronisations (Journalisation exigée par la
    fiche) — permet de voir si la collecte automatique de 2h du matin
    a bien tourné, ou si elle a échoué et pourquoi."""
    logs = session.query(SyncLog).order_by(SyncLog.started_at.desc()).limit(limit).all()
    return {
        "logs": [
            {
                "id": log.id,
                "started_at": log.started_at.isoformat() if log.started_at else None,
                "finished_at": log.finished_at.isoformat() if log.finished_at else None,
                "status": log.status,
                "trigger": log.trigger,
                "total_collected": log.total_collected,
                "new_count": log.new_count,
                "updated_count": log.updated_count,
                "alerts_created": log.alerts_created,
                "error_message": log.error_message,
            }
            for log in logs
        ]
    }


# ===== LANCEMENT =====

if __name__ == "__main__":
    import uvicorn
    print("=" * 50)
    print("🚀 VULNWATCH API")
    print("=" * 50)
    print("🌐 http://127.0.0.1:8000")
    print("🌐 http://127.0.0.1:8000/api/vulnerabilities")
    print("🌐 http://127.0.0.1:8000/api/health")
    print("🌐 http://127.0.0.1:8000/api/export/pdf")
    print("=" * 50)
    uvicorn.run(app, host="127.0.0.1", port=8000)