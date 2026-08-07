
const SEVERITY = {
    critical: { color: "#D8323F", label: "CRITIQUE" },
    high: { color: "#f67206", label: "ÉLEVÉE" },
    medium: { color: "#C89A15", label: "MOYENNE" },
    low: { color: "#2E7CD6", label: "FAIBLE" },
    unscored: { color: "#8A93A0", label: "NON ÉVALUÉE" },
};

let ALL_DATA = [];
let state = { 
    query: "", 
    severity: "all", 
    vendor: "all",
    product: "all",
    kevOnly: false,
    min_score: "",
    max_score: "",
    limit: 50,
    offset: 0
};
let charts = {};

// ===== TOAST =====
function showToast(message, type = "info", duration = 5000) {
    const oldToasts = document.querySelectorAll('.vuln-toast');
    oldToasts.forEach(t => t.remove());
    
    const toast = document.createElement('div');
    toast.className = 'vuln-toast';
    
    const colors = {
        critical: '#D8323F',
        high: '#f67206',
        medium: '#C89A15',
        info: '#2E7CD6',
        success: '#0E9C82',
        warning: '#F2994A'
    };
    const icons = {
        critical: '🚨',
        high: '⚠️',
        medium: '📌',
        info: 'ℹ️',
        success: '✅',
        warning: '⚡'
    };
    
    const bgColor = colors[type] || colors.info;
    const icon = icons[type] || icons.info;
    
    toast.style.cssText = `
        position: fixed;
        bottom: 24px;
        right: 24px;
        background: ${bgColor};
        color: white;
        padding: 16px 24px;
        border-radius: 12px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.25);
        z-index: 10000;
        max-width: 420px;
        font-family: 'Inter', sans-serif;
        font-size: 14px;
        font-weight: 500;
        animation: slideInToast 0.4s ease;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 12px;
        border: 1px solid rgba(255,255,255,0.15);
        backdrop-filter: blur(4px);
        transition: opacity 0.3s ease, transform 0.3s ease;
    `;
    
    toast.innerHTML = `
        <span style="font-size: 22px;">${icon}</span>
        <span>${message}</span>
        <span style="margin-left:auto;font-size:12px;opacity:0.7;cursor:pointer;" onclick="this.parentElement.remove()">✕</span>
    `;
    
    toast.addEventListener('click', () => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(100px)';
        setTimeout(() => toast.remove(), 300);
    });
    
    document.body.appendChild(toast);
    
    setTimeout(() => {
        if (toast.parentElement) {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100px)';
            setTimeout(() => toast.remove(), 300);
        }
    }, duration);
}

// ===== STYLES =====
const toastStyle = document.createElement("style");
toastStyle.textContent = `
    @keyframes slideInToast {
        from { transform: translateX(100px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
`;
document.head.appendChild(toastStyle);

// ===== ALERTES =====
let previousCriticalIds = new Set();

function checkNewCriticalCVEs(newData) {
    if (!newData || newData.length === 0) return;
    
    const critical = newData.filter(v => v.severity === "critical");
    const currentIds = new Set(critical.map(v => v.id));
    const newCritical = critical.filter(v => !previousCriticalIds.has(v.id));
    
    if (newCritical.length > 0) {
        newCritical.sort((a, b) => {
            const da = a.published ? new Date(a.published).getTime() : 0;
            const db = b.published ? new Date(b.published).getTime() : 0;
            return db - da;
        });
        
        newCritical.forEach((cve, index) => {
            setTimeout(() => {
                showToast(`🚨 ${cve.vendor} — ${cve.id}: ${cve.severity.toUpperCase()}`, "critical", 8000);
            }, index * 1500);
        });
        
        updateAlertBadge(newCritical.length);
    }
    previousCriticalIds = currentIds;
}

function updateAlertBadge(count) {
    const existing = document.getElementById('alertBadge');
    if (existing) existing.remove();
    
    if (count > 0) {
        const badge = document.createElement('span');
        badge.id = 'alertBadge';
        badge.textContent = count;
        const navItem = document.querySelector('.nav-item[data-view="list"]');
        if (navItem) {
            navItem.style.position = 'relative';
            navItem.appendChild(badge);
        }
    }
}


async function loadAlertsPanel() {
    const data = await fetchAlerts();
    renderAlertBellBadge(data.unread_count || 0);
    renderAlertsListPanel(data.alerts || []);
}

function renderAlertBellBadge(count) {
    const badge = document.getElementById("alertBellBadge");
    if (!badge) return;
    if (count > 0) {
        badge.textContent = count > 9 ? "9+" : count;
        badge.style.cssText = `
            display:inline-block;position:absolute;top:2px;right:2px;
            background:#D8323F;color:white;border-radius:50%;
            font-size:9px;font-weight:700;min-width:14px;height:14px;
            line-height:14px;text-align:center;padding:0 3px;
        `;
    } else {
        badge.style.display = "none";
    }
}

function renderAlertsListPanel(alerts) {
    const container = document.getElementById("alertsListPanel");
    if (!container) return;

    if (alerts.length === 0) {
        container.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-faint);font-size:12px;">Aucune alerte pour le moment.</div>`;
        return;
    }

    container.innerHTML = alerts.map(a => `
        <div class="alert-item" onclick="handleAlertClick(${a.id}, '${a.cve_id}')"
             style="padding:10px 16px;border-bottom:1px solid var(--border);cursor:pointer;
                    ${a.acknowledged ? "opacity:0.55;" : ""}">
            <div style="display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;
                        color:${a.reason === 'new_critical' ? '#D8323F' : '#f67206'};">
                ${a.reason === 'new_critical' ? '🔴 Nouvelle CVE critique' : '⚠️ Nouvellement KEV'}
                ${!a.acknowledged ? '<span style="width:6px;height:6px;border-radius:50%;background:#0E9C82;margin-left:4px;"></span>' : ''}
            </div>
            <div style="font-size:12px;margin-top:3px;">${a.message}</div>
            <div style="font-size:10px;color:var(--text-faint);margin-top:3px;">
                ${new Date(a.created_at).toLocaleString("fr-FR")}
            </div>
        </div>
    `).join("");
}

function handleAlertClick(alertId, cveId) {
    ackAlert(alertId).then(() => loadAlertsPanel());
    const panel = document.getElementById("alertsPanel");
    if (panel) panel.style.display = "none";
    if (ALL_DATA.find(v => v.id === cveId)) {
        document.querySelector('.nav-item[data-view="list"]')?.click();
        openDrawer(cveId);
    }
}

// ===== SYNC =====
function updateSyncTime(status = "success") {
    const el = document.getElementById("lastSyncText");
    if (!el) return;
    if (status === "loading") { el.textContent = "🔄 Chargement..."; return; }
    if (status === "error") { el.textContent = "❌ Erreur"; return; }
    const now = new Date();
    el.textContent = now.toLocaleTimeString("fr-FR", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// ===== CHARGEMENT =====
async function loadData() {
    updateSyncTime("loading");
    
    try {
        const data = await fetchVulnerabilities(state);
        ALL_DATA = data;
        console.log(`📊 ${ALL_DATA.length} CVE chargées`);
        
        if (ALL_DATA.length > 0) {
            console.log("📊 Exemple:", ALL_DATA[0]);
        }
        
        checkNewCriticalCVEs(data);
        render();
        updateSyncTime("success");
    } catch (e) {
        console.error("❌ Erreur:", e);
        try {
            const res = await fetch("data/data.json?_=" + Date.now());
            const json = await res.json();
            ALL_DATA = json.vulnerabilities.map(v => ({ 
                ...v, 
                published: v.published ? new Date(v.published) : null,
                score: v.cvss_score || v.score || 0
            }));
            checkNewCriticalCVEs(ALL_DATA);
            render();
            updateSyncTime("success");
            showToast("⚠️ Données locales chargées", "warning", 4000);
        } catch (err) {
            updateSyncTime("error");
            showToast("❌ Erreur de chargement", "critical", 5000);
        }
    }
}

// ===== RENDU =====
function render() {
    renderKPIs();
    renderCharts();
    renderCriticalList();
    renderFilters();
    renderList();
    populateVendorFilter();
    populateProductFilter();
}

// ===== STATS =====
async function renderKPIs() {
    const stats = await fetchStats();
    if (!stats) {
        const total = ALL_DATA.length;
        const critical = ALL_DATA.filter(v => v.severity === "critical").length;
        const kev = ALL_DATA.filter(v => v.kev === true).length;
        const patched = ALL_DATA.filter(v => v.patch_available === true).length;
        
        const kpis = [
            { label: "Total suivies", value: total, color: "#2E7CD6" },
            { label: "Critiques", value: critical, color: "#D8323F" },
            { label: "Exploitées (KEV)", value: kev, color: "#f67206" },
            { label: "Correctifs", value: patched, color: "#0E9C82" },
        ];
        
        const grid = document.getElementById("kpiGrid");
        if (grid) {
            grid.innerHTML = kpis.map(k => `
                <div class="kpi-card">
                    <div class="kpi-label">${k.label}</div>
                    <div class="kpi-value" style="color:${k.color};">${k.value}</div>
                </div>
            `).join("");
        }
        return;
    }
    
    const kpis = [
        { label: "Total suivies", value: stats.total || 0, color: "#2E7CD6" },
        { label: "Critiques", value: stats.critical || 0, color: "#D8323F" },
        { label: "Exploitées (KEV)", value: stats.kev_count || 0, color: "#f67206" },
        { label: "Correctifs", value: stats.patch_available || 0, color: "#0E9C82" },
    ];
    
    const grid = document.getElementById("kpiGrid");
    if (grid) {
        grid.innerHTML = kpis.map(k => `
            <div class="kpi-card">
                <div class="kpi-label">${k.label}</div>
                <div class="kpi-value" style="color:${k.color};">${k.value}</div>
            </div>
        `).join("");
    }
}

// ========== GRAPHIQUES ==========
function renderCharts() {
    renderTimelineChart();
    renderSeverityChart();
    renderVendorChart();
}

function renderTimelineChart() {
    const canvas = document.getElementById("timelineChart");
    if (!canvas) return;
    
    const days = [];
    const today = new Date();
    for (let i = 13; i >= 0; i--) {
        const d = new Date(today);
        d.setDate(d.getDate() - i);
        const count = ALL_DATA.filter(v => {
            if (!v.published) return false;
            const pub = new Date(v.published);
            return pub.toDateString() === d.toDateString();
        }).length;
        days.push({ 
            label: d.toLocaleDateString("fr-FR", { day: "2-digit", month: "2-digit" }), 
            count 
        });
    }
    
    const ctx = canvas.getContext('2d');
    if (charts.timeline) charts.timeline.destroy();
    
    charts.timeline = new Chart(ctx, {
        type: 'line',
        data: {
            labels: days.map(d => d.label),
            datasets: [{
                label: 'Nouvelles CVE',
                data: days.map(d => d.count),
                borderColor: "#0E9C82",
                backgroundColor: "rgba(14,156,130,0.12)",
                fill: true,
                tension: 0.35,
                pointRadius: 3,
                pointBackgroundColor: "#0E9C82",
                borderWidth: 2,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#1A222C",
                    borderColor: "#2A3340",
                    borderWidth: 1,
                }
            },
            scales: {
                x: { grid: { display: false }, ticks: { color: "#8A93A0", font: { size: 10 } } },
                y: { grid: { color: "#E1E4E9" }, ticks: { color: "#8A93A0", font: { size: 10 }, stepSize: 1 }, beginAtZero: true }
            }
        }
    });
}

function renderSeverityChart() {
    const canvas = document.getElementById("severityChart");
    if (!canvas) return;
    
    const dist = Object.keys(SEVERITY).map(s => ({
        label: SEVERITY[s].label,
        value: ALL_DATA.filter(v => v.severity === s).length,
        color: SEVERITY[s].color,
    }));
    
    const ctx = canvas.getContext('2d');
    if (charts.severity) charts.severity.destroy();
    
    charts.severity = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: dist.map(d => d.label),
            datasets: [{ 
                data: dist.map(d => d.value), 
                backgroundColor: dist.map(d => d.color),
                borderWidth: 0 
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "68%",
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#1A222C",
                    borderColor: "#2A3340",
                    borderWidth: 1,
                    callbacks: {
                        label: function(context) {
                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                            const percentage = total > 0 ? Math.round((context.parsed / total) * 100) : 0;
                            return `${context.label}: ${context.parsed} (${percentage}%)`;
                        }
                    }
                }
            }
        }
    });
    
    const legendEl = document.getElementById("severityLegend");
    if (legendEl) {
        legendEl.innerHTML = dist.map(d => `
            <div class="legend-item">
                <span class="legend-dot" style="background:${d.color};"></span>
                ${d.label} (${d.value})
            </div>
        `).join("");
    }
}

function renderVendorChart() {
    const canvas = document.getElementById("vendorChart");
    if (!canvas) return;
    
    const counts = {};
    ALL_DATA.forEach(v => {
        if (v.vendor) {
            counts[v.vendor] = (counts[v.vendor] || 0) + 1;
        }
    });
    
    const top = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8);
    
    const ctx = canvas.getContext('2d');
    if (charts.vendor) charts.vendor.destroy();
    
    charts.vendor = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: top.map(t => t[0]),
            datasets: [{ 
                data: top.map(t => t[1]), 
                backgroundColor: "#2E7CD6",
                borderRadius: 4,
                barThickness: 14,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: "#1A222C",
                    borderColor: "#2A3340",
                    borderWidth: 1,
                }
            },
            scales: {
                x: { 
                    grid: { color: "#E1E4E9" }, 
                    ticks: { color: "#8A93A0", font: { size: 10 }, stepSize: 1 }, 
                    beginAtZero: true 
                },
                y: { 
                    grid: { display: false }, 
                    ticks: { color: "#5B6472", font: { size: 10 } } 
                }
            }
        }
    });
}

// ========== LISTE CRITIQUE ==========
function renderCriticalList() {
    const container = document.getElementById("criticalList");
    if (!container) return;
    
    const criticals = ALL_DATA
        .filter(v => v.severity === "critical")
        .sort((a, b) => {
            const da = a.published ? new Date(a.published).getTime() : 0;
            const db = b.published ? new Date(b.published).getTime() : 0;
            return db - da;
        })
        .slice(0, 5);
    
    if (criticals.length === 0) {
        container.innerHTML = `<div style="color:var(--text-faint);font-size:12px;">Aucune vulnérabilité critique.</div>`;
        return;
    }
    
    container.innerHTML = criticals.map(v => `
        <div class="critical-item" onclick="openDrawer('${v.id}')">
            ${ringSVG(v.score || 0, v.severity, 36, 3.5, v.unscored)}
            <div class="critical-item-body">
                <div class="critical-item-id">${v.id}</div>
                <div class="critical-item-meta">${v.vendor} — ${v.product}</div>
                <div class="critical-item-desc">${v.description ? v.description.substring(0, 80) + (v.description.length > 80 ? '...' : '') : 'Aucune description'}</div>
            </div>
        </div>
    `).join("");
}

// ========== FILTRES ==========
function renderFilters() {
    const chipsEl = document.getElementById("severityChips");
    if (chipsEl) {
        const options = ["all", ...Object.keys(SEVERITY)];
        chipsEl.innerHTML = options.map(s => {
            const active = state.severity === s;
            const color = s === "all" ? "#0E9C82" : SEVERITY[s].color;
            const label = s === "all" ? "Toutes" : SEVERITY[s].label;
            return `<button class="chip ${active ? "active" : ""}" 
                    style="${active ? `background:${color};color:#FFFFFF;` : ""}" 
                    data-sev="${s}">${label}</button>`;
        }).join("");
        
        chipsEl.querySelectorAll(".chip").forEach(chip => {
            chip.addEventListener("click", () => {
                state.severity = chip.dataset.sev;
                renderFilters();
                renderList();
            });
        });
    }
    
    const kevBtn = document.getElementById("kevToggle");
    if (kevBtn) {
        kevBtn.classList.toggle("active-kev", state.kevOnly);
        kevBtn.onclick = () => {
            state.kevOnly = !state.kevOnly;
            renderFilters();
            renderList();
        };
    }
    
    const minScoreInput = document.getElementById("minScore");
    const maxScoreInput = document.getElementById("maxScore");
    if (minScoreInput) {
        minScoreInput.addEventListener("input", (e) => {
            state.min_score = e.target.value;
            renderList();
        });
    }
    if (maxScoreInput) {
        maxScoreInput.addEventListener("input", (e) => {
            state.max_score = e.target.value;
            renderList();
        });
    }
}

// ========== LISTE ==========
function renderList() {
    const container = document.getElementById("vulnTable");
    if (!container) return;
    
    const filtered = ALL_DATA.filter(v => {
        if (state.severity !== "all" && v.severity !== state.severity) return false;
        if (state.vendor !== "all" && v.vendor !== state.vendor) return false;
        if (state.product !== "all" && v.product !== state.product) return false;
        if (state.kevOnly && !v.kev) return false;
        
        const score = v.score || 0;
        if (state.min_score && score < parseFloat(state.min_score)) return false;
        if (state.max_score && score > parseFloat(state.max_score)) return false;
        
        if (state.query) {
            const q = state.query.toLowerCase();
            const searchText = `${v.id} ${v.vendor} ${v.product} ${v.description}`.toLowerCase();
            if (!searchText.includes(q)) return false;
        }
        return true;
    }).sort((a, b) => {
        const da = a.published ? new Date(a.published).getTime() : 0;
        const db = b.published ? new Date(b.published).getTime() : 0;
        return db - da;
    });
    
    const countEl = document.getElementById("resultCount");
    if (countEl) {
        countEl.textContent = `${filtered.length} résultat(s)`;
    }
    
    if (filtered.length === 0) {
        container.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-faint);">Aucune vulnérabilité trouvée.</div>`;
        return;
    }
    
    container.innerHTML = filtered.map(v => `
        <div class="table-row" onclick="openDrawer('${v.id}')">
            ${ringSVG(v.score || 0, v.severity, 34, 3.5, v.unscored)}
            <div class="col-id">${v.id}</div>
            <div class="col-product">
                <div class="p-name">${v.product || 'Inconnu'}</div>
                <div class="p-vendor">${v.vendor || 'Inconnu'}</div>
            </div>
            <div class="col-desc">${v.description ? v.description.substring(0, 120) + (v.description.length > 120 ? '...' : '') : 'Aucune description'}</div>
            <div class="col-badges">${badgeHTML(v.severity)}${v.kev ? kevBadgeHTML() : ""}</div>
            <div class="col-date">${v.published ? timeAgo(new Date(v.published)) : "Inconnue"}</div>
            <span class="patch-icon">${patchIcon(v.patch_available)}</span>
            <svg class="chevron" width="15" height="15" viewBox="0 0 24 24" fill="none">
                <path d="M9 6l6 6-6 6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
        </div>
    `).join("");
}

async function populateVendorFilter() {
    const select = document.getElementById("vendorFilter");
    if (!select) return;
    
    const vendors = await fetchVendors();
    select.innerHTML = `<option value="all">Tous les éditeurs</option>` +
        vendors.map(v => `<option value="${v}">${v}</option>`).join("");
    select.onchange = (e) => {
        state.vendor = e.target.value;
        state.product = "all";
        populateProductFilter();
        renderList();
    };
}

async function populateProductFilter() {
    const select = document.getElementById("productFilter");
    if (!select) return;
    
    const vendor = state.vendor !== "all" ? state.vendor : null;
    const products = await fetchProducts(vendor);
    select.innerHTML = `<option value="all">Tous les produits</option>` +
        products.map(p => `<option value="${p}">${p}</option>`).join("");
    select.onchange = (e) => {
        state.product = e.target.value;
        renderList();
    };
}

// ===== UTILITAIRES =====
function timeAgo(date) {
    if (!date) return "Inconnue";
    const diffMs = Date.now() - date.getTime();
    const mins = Math.floor(diffMs / 60000);
    if (mins < 1) return "à l'instant";
    if (mins < 60) return `il y a ${mins} min`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `il y a ${hours} h`;
    const days = Math.floor(hours / 24);
    if (days === 1) return "hier";
    if (days < 30) return `${days}j`;
    return date.toLocaleDateString("fr-FR", { day: "2-digit", month: "short" });
}

function ringSVG(score, severity, size = 40, strokeW = 3.5, unscored = false) {
    const r = (size - strokeW * 2) / 2;
    const c = 2 * Math.PI * r;
    const pct = unscored ? 0 : Math.min((score || 0) / 10, 1);
    const color = SEVERITY[severity]?.color || "#8A93A0";
    const label = unscored ? "N/A" : (score || 0).toFixed(1);
    return `
        <div class="ring" style="width:${size}px;height:${size}px;">
            <svg width="${size}" height="${size}">
                <circle cx="${size/2}" cy="${size/2}" r="${r}" stroke="#E1E4E9" stroke-width="${strokeW}" fill="none" />
                <circle cx="${size/2}" cy="${size/2}" r="${r}" stroke="${color}" stroke-width="${strokeW}" fill="none"
                    stroke-dasharray="${c}" stroke-dashoffset="${c * (1 - pct)}" stroke-linecap="round" />
            </svg>
            <span class="ring-score" style="font-size:${unscored ? size*0.22 : size*0.28}px;color:${color};">${label}</span>
        </div>`;
}

function badgeHTML(severity) {
    const s = SEVERITY[severity] || SEVERITY.unscored;
    return `<span class="badge" style="color:${s.color};background:${s.color}1A;border:1px solid ${s.color}40;">
        <span class="badge-dot" style="background:${s.color};"></span>${s.label}
    </span>`;
}

function kevBadgeHTML() {
    return `<span class="badge kev-badge">
        <svg width="10" height="10" viewBox="0 0 24 24" fill="none">
            <path d="M12 9v4M12 17h.01M10.3 3.9L1.8 18a2 2 0 001.7 3h17a2 2 0 001.7-3L13.7 3.9a2 2 0 00-3.4 0z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        Exploitée activement
    </span>`;
}

function patchIcon(available) {
    return available
        ? `<svg width="15" height="15" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9" stroke="#0E9C82" stroke-width="1.6"/>
            <path d="M8 12l3 3 5-6" stroke="#0E9C82" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>`
        : `<svg width="15" height="15" viewBox="0 0 24 24" fill="none">
            <circle cx="12" cy="12" r="9" stroke="#8A93A0" stroke-width="1.6"/>
        </svg>`;
}

// ===== DETAIL DRAWER =====
function openDrawer(id) {
    const v = ALL_DATA.find(x => x.id === id);
    if (!v) {
        console.warn(`CVE ${id} non trouvée`);
        return;
    }
    
    const drawer = document.getElementById("drawer");
    if (!drawer) return;
    
    const sourceUrl = v.source_url || `https://nvd.nist.gov/vuln/detail/${v.id}`;
    const referencesHtml = v.references && v.references.length > 0 
        ? v.references.map(ref => `
            <a class="ref-link" href="${ref}" target="_blank" rel="noopener">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
                    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M15 3h6v6M10 14L21 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                ${ref.length > 60 ? ref.substring(0, 60) + "..." : ref}
            </a>
        `).join("")
        : `
            <a class="ref-link" href="${sourceUrl}" target="_blank" rel="noopener">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none">
                    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                    <path d="M15 3h6v6M10 14L21 3" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
                Voir sur NVD
            </a>
        `;
    
    drawer.innerHTML = `
        <div class="drawer-header">
            <div>
                <div class="drawer-id">${v.id}</div>
                <div class="drawer-meta">${v.vendor || 'Inconnu'} — ${v.product || 'Inconnu'}</div>
                ${v.versions ? `<div class="drawer-versions" style="font-size:12px;color:var(--text-dim);margin-top:4px;">📦 Versions: ${v.versions}</div>` : ''}
            </div>
            <button class="drawer-close" onclick="closeDrawer()">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                    <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                </svg>
            </button>
        </div>
        <div class="drawer-score-row">
            ${ringSVG(v.score || 0, v.severity, 54, 4, v.unscored)}
            <div>
                ${badgeHTML(v.severity)}
                <div class="drawer-score-sub">Score CVSS ${(v.score || 0).toFixed(1)}/10</div>
            </div>
        </div>
        ${v.kev ? `<div class="kev-alert">${kevBadgeHTML()}<span>Cette vulnérabilité est activement exploitée (catalogue CISA KEV).</span></div>` : ""}
        <div>
            <div class="section-label">Description</div>
            <div class="section-body">${v.description || "Aucune description disponible"}</div>
        </div>
        <div class="info-grid">
            <div class="info-box">
                <div class="info-box-label">📅 Publiée</div>
                <div class="info-box-value">${v.published ? new Date(v.published).toLocaleDateString("fr-FR", { year: "numeric", month: "long", day: "numeric" }) : "Inconnue"}</div>
            </div>
            <div class="info-box">
                <div class="info-box-label">🔄 Dernière mise à jour</div>
                <div class="info-box-value">${v.last_modified ? new Date(v.last_modified).toLocaleDateString("fr-FR", { year: "numeric", month: "long", day: "numeric" }) : "Inconnue"}</div>
            </div>
        </div>
        <div class="patch-status-box">
            ${patchIcon(v.patch_available)}
            ${v.patch_available ? "✅ Correctif disponible" : "❌ Aucun correctif publié"}
        </div>
        <div>
            <div class="section-label">🔗 Source</div>
            ${referencesHtml}
        </div>
        <div style="margin-top:8px;font-size:11px;color:var(--text-faint);">
            Source: ${v.source || "NVD"}
        </div>
    `;
    
    document.getElementById("overlay").classList.add("open");
}

function closeDrawer() {
    document.getElementById("overlay").classList.remove("open");
}

// ===== EXPORTS =====
function exportCSV() {
    const filters = {
        vendor: state.vendor !== "all" ? state.vendor : undefined,
        product: state.product !== "all" ? state.product : undefined,
        severity: state.severity !== "all" ? state.severity.toUpperCase() : undefined,
        kevOnly: state.kevOnly,
        min_score: state.min_score || undefined,
        max_score: state.max_score || undefined
    };
    exportCsv(filters);
}

// ========== EXPORT PDF ==========
function exportPDF() {
    const filters = {
        vendor: state.vendor !== "all" ? state.vendor : undefined,
        product: state.product !== "all" ? state.product : undefined,
        severity: state.severity !== "all" ? state.severity.toUpperCase() : undefined,
        kevOnly: state.kevOnly,
        min_score: state.min_score || undefined,
        max_score: state.max_score || undefined
    };
    
    exportPdf(filters);
    showToast("📄 Export PDF en cours...", "info", 3000);
}

function refreshData() {
    const btn = document.getElementById("refreshBtn");
    if (btn) { btn.textContent = "⏳"; btn.disabled = true; }
    updateSyncTime("loading");
    showToast("🔄 Mise à jour des données...", "info", 2000);
    
    loadData().then(() => {
        if (btn) { btn.textContent = "✓"; btn.disabled = false; setTimeout(() => { btn.textContent = "↻"; }, 2000); }
        showToast("✅ Données mises à jour", "success", 3000);
    }).catch(() => {
        if (btn) { btn.textContent = "↻"; btn.disabled = false; }
        updateSyncTime("error");
        showToast("❌ Erreur de mise à jour", "critical", 4000);
    });
}

function scheduleMidnightRefresh() {
    const now = new Date();
    const nextMidnight = new Date(now);
    nextMidnight.setHours(24, 0, 0, 0);
    const msUntilMidnight = nextMidnight.getTime() - now.getTime();

    setTimeout(() => {
        console.log("🌙 Minuit — rafraîchissement automatique");
        showToast("🌙 Mise à jour quotidienne", "info", 3000);
        loadData();
        setInterval(() => {
            console.log("🌙 Minuit — rafraîchissement automatique");
            showToast("🌙 Mise à jour quotidienne", "info", 3000);
            loadData();
        }, 24 * 60 * 60 * 1000);
    }, msUntilMidnight);
}

// ===== ÉVÉNEMENTS =====
document.addEventListener("DOMContentLoaded", function() {
    const overlay = document.getElementById("overlay");
    if (overlay) overlay.addEventListener("click", closeDrawer);
    
    const searchInput = document.getElementById("searchInput");
    if (searchInput) {
        searchInput.addEventListener("input", (e) => {
            state.query = e.target.value;
            renderList();
        });
    }
    
    const exportBtn = document.getElementById("exportBtn");
    if (exportBtn) {
        exportBtn.addEventListener("click", exportCSV);
    }
    
    const pdfBtn = document.getElementById("exportPDFBtn");
    if (pdfBtn) {
        pdfBtn.addEventListener("click", exportPDF);
    }
    
    const refreshBtn = document.getElementById("refreshBtn");
    if (refreshBtn) {
        refreshBtn.addEventListener("click", refreshData);
    }
    
    const alertBell = document.getElementById("alertBell");
    const alertsPanel = document.getElementById("alertsPanel");
    if (alertBell && alertsPanel) {
        alertBell.addEventListener("click", (e) => {
            e.stopPropagation();
            const isOpen = alertsPanel.style.display === "block";
            alertsPanel.style.display = isOpen ? "none" : "block";
            if (!isOpen) loadAlertsPanel();
        });
        document.addEventListener("click", (e) => {
            if (!alertsPanel.contains(e.target) && e.target !== alertBell) {
                alertsPanel.style.display = "none";
            }
        });
    }
    const markAllReadBtn = document.getElementById("markAllReadBtn");
    if (markAllReadBtn) {
        markAllReadBtn.addEventListener("click", () => {
            ackAllAlerts().then(() => loadAlertsPanel());
        });
    }
    
    document.querySelectorAll(".nav-item").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".nav-item").forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const view = btn.dataset.view;
            const dashboard = document.getElementById("view-dashboard");
            const list = document.getElementById("view-list");
            if (dashboard) dashboard.style.display = view === "dashboard" ? "flex" : "none";
            if (list) list.style.display = view === "list" ? "flex" : "none";
        });
    });
    
    loadData();
    loadAlertsPanel();
    setInterval(loadAlertsPanel, 60000);
    scheduleMidnightRefresh();
});

// ===== RESIZE =====
window.addEventListener('resize', function() {
    Object.keys(charts).forEach(key => {
        if (charts[key] && charts[key].resize) charts[key].resize();
    });
});