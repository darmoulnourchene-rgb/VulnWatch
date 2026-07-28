"""
collect_data.py
================
Collecteur réel — NVD + CISA KEV + Fortinet PSIRT + Palo Alto PSIRT.

Différences par rapport à la version précédente :
- Écrit désormais dans la base SQLite (via SQLAlchemy) au lieu d'un simple
  fichier JSON — voir models.py / database.py (Phase B1).
- Garde un export data.json en plus, comme copie de secours utilisée par
  le frontend si l'API est injoignable (fallback déjà prévu dans api_fast.js).
- Ajoute un deuxième flux PSIRT (Palo Alto), en plus de Fortinet.
- Suit la liste de TOUS les produits affectés par CVE (pas un seul).
- Génère des alertes (Phase B5) quand une CVE est nouvellement vue comme
  CRITICAL, ou nouvellement marquée KEV, sur un vendeur suivi.

Lancer avec :  python3 collect_data.py
"""

import json
import os
import re
import time
from datetime import datetime, timedelta

import requests

try:
    import feedparser
except ImportError:
    feedparser = None
    print("⚠️  feedparser non installé — les flux PSIRT seront ignorés (pip install feedparser)")

from Database import init_db, SessionLocal
from Models import Vulnerability, Alert, SyncLog


# ===== CONFIGURATION =====

NVD_API_KEY = ""  # optionnel — voir COLLECT_README.md
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# ⚠️ À vérifier vous-même : les URLs de flux RSS PSIRT changent parfois.
# Cherchez "<vendeur> PSIRT RSS feed" si l'une de ces deux ne répond plus.
FORTINET_PSIRT_RSS = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
PALOALTO_PSIRT_RSS = "https://security.paloaltonetworks.com/rss.xml"

VENDORS = {
    "Palo Alto Networks": "Palo Alto",
    "Fortinet": "Fortinet",
    "Cisco": "Cisco",
    "Microsoft Defender": "Microsoft Defender",
    "VMware": "VMware",
    "CrowdStrike": "CrowdStrike",
    "SentinelOne": "SentinelOne",
    "Check Point": "Check Point",
    "Sophos": "Sophos",
    "Trend Micro": "Trend Micro",
    "ESET": "ESET",
    "Kaspersky": "Kaspersky",
    "Bitdefender": "Bitdefender",
}

DAYS_BACK = 120  # ⚠️ NVD refuse tout écart pubStartDate/pubEndDate > 120 jours
RESULTS_PER_VENDOR = 15
NVD_DELAY = 6.5 if not NVD_API_KEY else 0.7

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
JSON_FALLBACK_PATH = os.path.join(BASE_DIR, "..", "frontend", "data", "data.json")

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")


# ===== ÉTAPE 1 : COLLECTE NVD (Tâche B2.1) =====

def fetch_nvd_by_keyword(keyword, results_per_page=15, days_back=DAYS_BACK):
    end = datetime.utcnow()
    start = end - timedelta(days=days_back)
    params = {
        "keywordSearch": keyword,
        "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": results_per_page,
    }
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        return resp.json().get("vulnerabilities", [])
    except requests.RequestException as e:
        # Tâche B2.4 — gestion des erreurs réseau : on log et on continue,
        # une source en panne ne doit pas bloquer les autres.
        print(f"❌ Erreur NVD pour '{keyword}': {e}")
        return []


def fetch_nvd_by_id(cve_id):
    params = {"cveId": cve_id}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        resp = requests.get(NVD_BASE_URL, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        items = resp.json().get("vulnerabilities", [])
        return items[0] if items else None
    except requests.RequestException as e:
        print(f"❌ Erreur NVD pour {cve_id}: {e}")
        return None


def extract_cvss(metrics):
    """Retourne (score, severity, unscored). unscored=True signifie que
    NVD n'a pas encore attribué de score CVSS à cette CVE (statut
    'Awaiting Analysis' — très fréquent pour les CVE très récentes).
    Dans ce cas on ne veut SURTOUT PAS afficher 0.0/LOW, qui laisserait
    croire à tort que la faille est bénigne."""
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m = metrics[key][0]
            score = m["cvssData"]["baseScore"]
            severity = m.get("baseSeverity") or m["cvssData"].get("baseSeverity", "")
            if not severity:
                if score >= 9.0: severity = "CRITICAL"
                elif score >= 7.0: severity = "HIGH"
                elif score >= 4.0: severity = "MEDIUM"
                else: severity = "LOW"
            return float(score), severity.upper(), False
    return 0.0, "UNSCORED", True


def extract_products(cve):
    """Extrait la liste des produits/versions affectés depuis les CPE
    fournis par NVD (configurations). Retombe sur une liste vide si NVD
    ne fournit pas de configuration exploitable."""
    products = set()
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                criteria = cpe_match.get("criteria", "")
                # cpe:2.3:a:vendor:product:version:...
                parts = criteria.split(":")
                if len(parts) > 4:
                    product_name = parts[4].replace("_", " ")
                    products.add(product_name)
    return sorted(products)


def normalize_nvd_item(item, vendor_label):
    cve = item.get("cve", {})
    cve_id = cve.get("id", "")
    descriptions = cve.get("descriptions", [])
    description = next((d["value"] for d in descriptions if d["lang"] == "en"), "Aucune description")
    metrics = cve.get("metrics", {})
    score, severity, unscored = extract_cvss(metrics)
    references = [r["url"] for r in cve.get("references", [])]
    patch_available = any("Patch" in r.get("tags", []) for r in cve.get("references", []))
    products = extract_products(cve)
    published = cve.get("published", "")

    if not published:
        print(f"⚠️  {cve_id} : champ 'published' vide dans la réponse NVD (cas rare, à surveiller)")

    return {
        "id": cve_id,
        "vendor": vendor_label,
        "product": products[0] if products else vendor_label,
        "products": products if products else [vendor_label],
        "description": description,
        "cvss_score": round(score, 1),
        "severity": severity,  # peut valoir "UNSCORED" si NVD n'a pas encore noté
        "unscored": unscored,
        "published_date": published,
        "patch_available": patch_available,
        "kev_status": False,  # mis à jour à l'étape 2
        "versions": ", ".join(products) if products else "Voir références",
        "references": references[:5] if references else [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "source": "NVD",
    }


def collect_from_nvd():
    all_items = []
    seen_ids = set()
    unscored_count = 0
    for vendor_label, keyword in VENDORS.items():
        print(f"📡 NVD — recherche '{keyword}'...")
        raw_items = fetch_nvd_by_keyword(keyword, RESULTS_PER_VENDOR)
        for item in raw_items:
            normalized = normalize_nvd_item(item, vendor_label)
            if normalized["id"] and normalized["id"] not in seen_ids:
                all_items.append(normalized)
                seen_ids.add(normalized["id"])
                if normalized["unscored"]:
                    unscored_count += 1
        time.sleep(NVD_DELAY)
    print(f"✅ NVD : {len(all_items)} CVE uniques collectées.")
    if unscored_count:
        print(f"ℹ️  {unscored_count}/{len(all_items)} CVE n'ont pas encore de score CVSS attribué par NVD")
        print(f"    (statut 'Awaiting Analysis' — normal pour des CVE très récentes, pas un bug)")
    return all_items


# ===== ÉTAPE 2 : CISA KEV (Tâche B2.2) =====

def fetch_kev_ids():
    try:
        resp = requests.get(CISA_KEV_URL, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        kev_ids = {v["cveID"] for v in data.get("vulnerabilities", [])}
        print(f"✅ CISA KEV : {len(kev_ids)} CVE exploitées activement (catalogue complet).")
        return kev_ids
    except requests.RequestException as e:
        print(f"❌ Erreur CISA KEV: {e}")
        return set()


def enrich_with_kev(items, kev_ids):
    for item in items:
        if item["id"] in kev_ids:
            item["kev_status"] = True
    return items


# ===== ÉTAPE 3 : FLUX PSIRT (Tâche B2.3) — Fortinet + Palo Alto =====

def collect_from_psirt_rss(rss_url, vendor_label, source_tag):
    if feedparser is None:
        return []
    print(f"📡 Flux PSIRT {vendor_label} (RSS)...")
    try:
        feed = feedparser.parse(rss_url)
    except Exception as e:
        print(f"❌ Erreur flux RSS {vendor_label}: {e}")
        return []

    cve_ids = set()
    for entry in feed.entries[:20]:
        text = f"{entry.get('title', '')} {entry.get('summary', '')}"
        for match in CVE_PATTERN.findall(text):
            cve_ids.add(match)

    print(f"   → {len(cve_ids)} CVE ID trouvées dans le flux PSIRT {vendor_label}.")

    items = []
    for cve_id in cve_ids:
        raw = fetch_nvd_by_id(cve_id)
        time.sleep(NVD_DELAY)
        if raw:
            normalized = normalize_nvd_item(raw, vendor_label)
            normalized["source"] = source_tag
            items.append(normalized)
    return items


# ===== ÉTAPE 4 : SAUVEGARDE EN BASE + ALERTES (Phases B3 et B5) =====

def upsert_and_alert(session, items):
    """Insère/met à jour chaque vulnérabilité (Tâche B3.2 — sans doublons,
    grâce à la clé primaire = CVE ID) et génère des alertes (Phase B5)
    quand une CVE est nouvellement CRITICAL ou nouvellement KEV."""
    new_count = 0
    updated_count = 0
    alerts_created = 0

    for item in items:
        existing = session.get(Vulnerability, item["id"])

        was_critical = existing.severity == "CRITICAL" if existing else False
        was_kev = existing.kev_status if existing else False

        if existing:
            existing.vendor = item["vendor"]
            existing.product = item["product"]
            existing.products = json.dumps(item["products"])
            existing.description = item["description"]
            existing.cvss_score = item["cvss_score"]
            existing.severity = item["severity"]
            existing.unscored = item.get("unscored", False)
            existing.published_date = item["published_date"]
            existing.patch_available = item["patch_available"]
            existing.kev_status = item["kev_status"]
            existing.versions = item["versions"]
            existing.references = json.dumps(item["references"])
            existing.source = item["source"]
            updated_count += 1
        else:
            existing = Vulnerability(
                id=item["id"],
                vendor=item["vendor"],
                product=item["product"],
                products=json.dumps(item["products"]),
                description=item["description"],
                cvss_score=item["cvss_score"],
                severity=item["severity"],
                unscored=item.get("unscored", False),
                published_date=item["published_date"],
                patch_available=item["patch_available"],
                kev_status=item["kev_status"],
                versions=item["versions"],
                references=json.dumps(item["references"]),
                source=item["source"],
            )
            session.add(existing)
            new_count += 1

        # ----- Règles d'alerte (Tâche B5.1) -----
        # 1. Nouvelle CVE CRITICAL sur un vendeur suivi (que ce soit une
        #    CVE totalement nouvelle, ou une CVE existante qui vient de
        #    passer à CRITICAL — ex: réévaluation de score par NVD)
        is_new_critical = item["severity"] == "CRITICAL" and not was_critical
        # 2. CVE nouvellement marquée KEV (exploitée activement)
        is_newly_kev = item["kev_status"] and not was_kev

        if is_new_critical:
            alerts_created += _create_alert_if_absent(
                session, item, "new_critical",
                f"Nouvelle CVE critique sur {item['vendor']} : {item['id']} (score {item['cvss_score']})"
            )
        if is_newly_kev:
            alerts_created += _create_alert_if_absent(
                session, item, "newly_kev",
                f"{item['id']} ({item['vendor']}) est maintenant activement exploitée (CISA KEV)"
            )

    session.commit()
    print(f"✅ Base de données : {new_count} nouvelles CVE, {updated_count} mises à jour, {alerts_created} alerte(s) générée(s).")
    return new_count, updated_count, alerts_created


def _create_alert_if_absent(session, item, reason, message):
    """Anti-doublon (Tâche B5.3) : vérifie qu'une alerte avec le même
    CVE ID + le même motif n'existe pas déjà avant d'en créer une."""
    existing_alert = (
        session.query(Alert)
        .filter(Alert.cve_id == item["id"], Alert.reason == reason)
        .first()
    )
    if existing_alert:
        return 0
    alert = Alert(cve_id=item["id"], vendor=item["vendor"], reason=reason, message=message)
    session.add(alert)
    return 1


def export_json_fallback(session):
    """Garde un data.json à jour, utilisé par le frontend uniquement si
    l'API est injoignable (voir le fallback dans api_fast.js)."""
    items = session.query(Vulnerability).all()
    payload = {
        "generated_at": datetime.now().isoformat(),
        "vulnerabilities": [
            {
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
            for v in items
        ],
    }
    os.makedirs(os.path.dirname(JSON_FALLBACK_PATH), exist_ok=True)
    with open(JSON_FALLBACK_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


# ===== ORCHESTRATION GLOBALE (Tâche B3.3) =====

def run_collection(trigger="manual"):
    """Point d'entrée unique — appelé par le script en ligne de commande,
    par le planificateur automatique (trigger='scheduled'), ou via
    /api/sync (trigger='api'). (Tâche B3.3 : 'une seule commande permet
    de peupler la base'.)

    Chaque exécution est journalisée dans la table sync_logs — exigé par
    la fiche de stage ('Journalisation des synchronisations')."""
    print("=" * 60)
    print("🚀 COLLECTE VULNWATCH — NVD + CISA KEV + PSIRT (Fortinet, Palo Alto)")
    print("=" * 60)

    init_db()

    log_session = SessionLocal()
    sync_log = SyncLog(started_at=datetime.utcnow(), status="running", trigger=trigger)
    log_session.add(sync_log)
    log_session.commit()
    log_id = sync_log.id

    try:
        all_items = collect_from_nvd()

        for rss_url, vendor_label, source_tag in [
            (FORTINET_PSIRT_RSS, "Fortinet", "NVD + Fortinet PSIRT"),
            (PALOALTO_PSIRT_RSS, "Palo Alto Networks", "NVD + Palo Alto PSIRT"),
        ]:
            psirt_items = collect_from_psirt_rss(rss_url, vendor_label, source_tag)
            existing_ids = {i["id"] for i in all_items}
            for item in psirt_items:
                if item["id"] not in existing_ids:
                    all_items.append(item)
                    existing_ids.add(item["id"])

        kev_ids = fetch_kev_ids()
        all_items = enrich_with_kev(all_items, kev_ids)

        session = SessionLocal()
        try:
            new_count, updated_count, alerts_created = upsert_and_alert(session, all_items)
            export_json_fallback(session)
        finally:
            session.close()

        log = log_session.get(SyncLog, log_id)
        log.finished_at = datetime.utcnow()
        log.status = "success"
        log.total_collected = len(all_items)
        log.new_count = new_count
        log.updated_count = updated_count
        log.alerts_created = alerts_created
        log_session.commit()

        print("=" * 60)
        print(f"✅ Collecte terminée — {len(all_items)} vulnérabilités traitées.")
        print("=" * 60)

    except Exception as e:
        log = log_session.get(SyncLog, log_id)
        log.finished_at = datetime.utcnow()
        log.status = "error"
        log.error_message = str(e)
        log_session.commit()
        print(f"❌ Collecte échouée : {e}")
        raise
    finally:
        log_session.close()


if __name__ == "__main__":
    run_collection(trigger="manual")