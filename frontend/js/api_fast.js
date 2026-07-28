// frontend/js/api_fast.js - VERSION COMPLÈTE
const API_BASE = "http://127.0.0.1:8000";

// ===== CONVERSION =====
function convertToFrontendFormat(item) {
    const isUnscored = item.unscored === true || item.severity === "UNSCORED";
    return {
        id: item.id || "",
        vendor: item.vendor || "Inconnu",
        product: item.product || "Inconnu",
        products_affected: item.products || [],
        description: item.description || "Aucune description",
        score: item.cvss_score || 0,
        severity: isUnscored ? "unscored" : (item.severity || "low").toLowerCase(),
        unscored: isUnscored,
        published: item.published_date || null,
        patch_available: item.patch_available || false,
        kev: item.kev_status || false,
        versions: item.versions || "Non spécifiée",
        source_url: item.references && item.references.length > 0 ? item.references[0] : "#",
        references: item.references || [],
        source: item.source || "NVD"
    };
}

// ===== APPELS API =====
async function fetchVulnerabilities(filters = {}) {
    const params = new URLSearchParams();
    if (filters.vendor && filters.vendor !== "all") params.append("vendor", filters.vendor);
    if (filters.product && filters.product !== "all") params.append("product", filters.product);
    if (filters.severity && filters.severity !== "all") params.append("severity", filters.severity.toUpperCase());
    if (filters.kevOnly) params.append("kev", "true");
    if (filters.min_score) params.append("min_score", filters.min_score);
    if (filters.max_score) params.append("max_score", filters.max_score);
    if (filters.search) params.append("search", filters.search);
    if (filters.limit) params.append("limit", filters.limit);
    if (filters.offset) params.append("offset", filters.offset);
    
    const url = `${API_BASE}/api/vulnerabilities?${params}`;
    
    try {
        console.log("📡 Appel API:", url);
        const response = await fetch(url);
        if (!response.ok) throw new Error(`Erreur API: ${response.status}`);
        const data = await response.json();
        console.log("📊 Données reçues:", data);
        
        const items = data.vulnerabilities || [];
        console.log(`📊 ${items.length} CVE chargées`);
        return items.map(convertToFrontendFormat);
    } catch (error) {
        console.error("❌ Erreur API:", error);
        return [];
    }
}

async function fetchCveDetail(id) {
    try {
        const response = await fetch(`${API_BASE}/api/vulnerabilities/${id}`);
        if (!response.ok) throw new Error("CVE non trouvée");
        return convertToFrontendFormat(await response.json());
    } catch (error) {
        console.error("❌ Erreur:", error);
        return null;
    }
}

async function fetchStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats`);
        if (!response.ok) throw new Error("Erreur stats");
        return await response.json();
    } catch (error) {
        console.error("❌ Erreur stats:", error);
        return {
            total: 0,
            critical: 0,
            high: 0,
            medium: 0,
            low: 0,
            kev_count: 0,
            patch_available: 0,
            by_vendor: {},
            last_30_days: 0
        };
    }
}

async function fetchVendors() {
    try {
        const response = await fetch(`${API_BASE}/api/vendors`);
        if (!response.ok) throw new Error("Erreur vendors");
        const data = await response.json();
        return data.vendors || [];
    } catch (error) {
        console.error("❌ Erreur vendors:", error);
        return [];
    }
}

async function fetchProducts(vendor) {
    try {
        const params = vendor ? `?vendor=${encodeURIComponent(vendor)}` : "";
        const response = await fetch(`${API_BASE}/api/products${params}`);
        if (!response.ok) throw new Error("Erreur products");
        const data = await response.json();
        return data.products || [];
    } catch (error) {
        console.error("❌ Erreur products:", error);
        return [];
    }
}

async function fetchAlerts() {
    try {
        const response = await fetch(`${API_BASE}/api/alerts`);
        if (!response.ok) throw new Error("Erreur alerts");
        return await response.json();
    } catch (error) {
        console.error("❌ Erreur alerts:", error);
        return { unread_count: 0, alerts: [] };
    }
}

async function ackAlert(alertId) {
    try {
        const response = await fetch(`${API_BASE}/api/alerts/${alertId}/ack`, { method: "POST" });
        if (!response.ok) throw new Error("Erreur ack");
        return await response.json();
    } catch (error) {
        console.error("❌ Erreur ack alert:", error);
        return null;
    }
}

async function ackAllAlerts() {
    try {
        const response = await fetch(`${API_BASE}/api/alerts/ack_all`, { method: "POST" });
        if (!response.ok) throw new Error("Erreur ack_all");
        return await response.json();
    } catch (error) {
        console.error("❌ Erreur ack all alerts:", error);
        return null;
    }
}

async function fetchSyncLogs() {
    try {
        const response = await fetch(`${API_BASE}/api/sync-logs`);
        if (!response.ok) throw new Error("Erreur sync-logs");
        return await response.json();
    } catch (error) {
        console.error("❌ Erreur sync-logs:", error);
        return { logs: [] };
    }
}

async function exportCsv(filters = {}) {
    const params = new URLSearchParams();
    if (filters.vendor && filters.vendor !== "all") params.append("vendor", filters.vendor);
    if (filters.product && filters.product !== "all") params.append("product", filters.product);
    if (filters.severity && filters.severity !== "all") params.append("severity", filters.severity.toUpperCase());
    if (filters.kevOnly) params.append("kev", "true");
    if (filters.min_score) params.append("min_score", filters.min_score);
    if (filters.max_score) params.append("max_score", filters.max_score);
    
    const url = `${API_BASE}/api/export/csv?${params}`;
    window.open(url, '_blank');
}

async function exportPdf(filters = {}) {
    const params = new URLSearchParams();
    if (filters.vendor && filters.vendor !== "all") params.append("vendor", filters.vendor);
    if (filters.product && filters.product !== "all") params.append("product", filters.product);
    if (filters.severity && filters.severity !== "all") params.append("severity", filters.severity.toUpperCase());
    if (filters.kevOnly) params.append("kev", "true");
    if (filters.min_score) params.append("min_score", filters.min_score);
    if (filters.max_score) params.append("max_score", filters.max_score);
    
    const url = `${API_BASE}/api/export/pdf?${params}`;
    try {
        window.open(url, '_blank');
        if (typeof showToast === 'function') {
            showToast("📄 Export PDF en cours...", "info", 3000);
        }
    } catch (error) {
        console.error("❌ Erreur export PDF:", error);
        if (typeof showToast === 'function') {
            showToast("❌ Erreur lors de l'export PDF", "critical", 4000);
        }
    }
}

async function checkHealth() {
    try {
        const response = await fetch(`${API_BASE}/api/health`);
        if (!response.ok) throw new Error("API non disponible");
        return await response.json();
    } catch (error) {
        console.error("❌ API hors ligne:", error);
        return { status: "unhealthy" };
    }
}