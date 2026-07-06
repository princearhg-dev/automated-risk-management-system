// dashboard.js - handles live updates and Chart.js visualisations
// all the charts on the main dashboard are initialised and refreshed here

let alertsTimeChart = null;
let severityPieChart = null;
let riskPieChart = null;

const SEVERITY_COLOURS = {
    "Critical": "#212529",
    "High":     "#dc3545",
    "Medium":   "#ffc107",
    "Low":      "#198754"
};

const RISK_COLOURS = {
    "Low":       "#198754",
    "Medium":    "#0dcaf0",
    "High":      "#ffc107",
    "Very High": "#dc3545",
    "Critical":  "#212529"
};

function updateLastUpdateTime() {
    const el = document.getElementById("last-update");
    if (el) {
        const now = new Date();
        el.textContent = "Updated " + now.toLocaleTimeString();
    }
}

// -- Summary stats --

function refreshSummary() {
    fetch("/api/summary")
        .then(r => r.json())
        .then(data => {
            const setEl = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = val;
            };
            setEl("stat-total-events", data.total_events);
            setEl("stat-total-alerts", data.total_alerts);
            setEl("stat-unacked", data.unacknowledged_alerts);
            setEl("stat-risk-level", data.highest_risk_level);
            updateLastUpdateTime();
        })
        .catch(err => console.warn("summary fetch failed:", err));
}

// -- Alerts over time (line chart) --

function buildAlertsTimeChart(labels, values) {
    const ctx = document.getElementById("alertsTimeChart");
    if (!ctx) return;

    if (alertsTimeChart) alertsTimeChart.destroy();

    alertsTimeChart = new Chart(ctx, {
        type: "line",
        data: {
            labels: labels,
            datasets: [{
                label: "Alerts",
                data: values,
                borderColor: "#0d6efd",
                backgroundColor: "rgba(13, 110, 253, 0.08)",
                fill: true,
                tension: 0.3,
                pointRadius: 3,
            }]
        },
        options: {
            responsive: true,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { maxTicksLimit: 8, font: { size: 11 } } },
                y: { beginAtZero: true, ticks: { stepSize: 1 } }
            }
        }
    });
}

function refreshAlertsTimeChart() {
    fetch("/api/alerts/over-time?hours=24")
        .then(r => r.json())
        .then(data => {
            const labels = data.map(d => d.hour.slice(11, 16)); // just HH:MM
            const values = data.map(d => d.count);
            buildAlertsTimeChart(labels, values);
        })
        .catch(err => console.warn("time chart fetch failed:", err));
}

// -- Severity pie chart --

function buildSeverityPie(data) {
    const ctx = document.getElementById("severityPieChart");
    if (!ctx) return;

    if (severityPieChart) severityPieChart.destroy();

    const labels = Object.keys(data);
    const values = Object.values(data);
    const bgColours = labels.map(l => SEVERITY_COLOURS[l] || "#6c757d");

    severityPieChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{ data: values, backgroundColor: bgColours }]
        },
        options: {
            plugins: { legend: { position: "bottom", labels: { font: { size: 11 } } } },
            responsive: true,
        }
    });
}

function refreshSeverityPie() {
    fetch("/api/alerts/by-severity")
        .then(r => r.json())
        .then(data => buildSeverityPie(data))
        .catch(err => console.warn("severity pie fetch failed:", err));
}

// -- Risk distribution pie chart --

function buildRiskPie(data) {
    const ctx = document.getElementById("riskPieChart");
    if (!ctx) return;

    if (riskPieChart) riskPieChart.destroy();

    const labels = Object.keys(data);
    const values = Object.values(data);
    const bgColours = labels.map(l => RISK_COLOURS[l] || "#6c757d");

    riskPieChart = new Chart(ctx, {
        type: "doughnut",
        data: {
            labels,
            datasets: [{ data: values, backgroundColor: bgColours }]
        },
        options: {
            plugins: { legend: { position: "bottom", labels: { font: { size: 11 } } } },
            responsive: true,
        }
    });
}

function refreshRiskPie() {
    fetch("/api/risk/distribution")
        .then(r => r.json())
        .then(data => buildRiskPie(data))
        .catch(err => console.warn("risk pie fetch failed:", err));
}

// -- Recent alerts table --

function severityBadge(severity) {
    const classes = {
        "Critical": "bg-dark",
        "High":     "bg-danger",
        "Medium":   "bg-warning text-dark",
        "Low":      "bg-success"
    };
    return `<span class="badge ${classes[severity] || 'bg-secondary'}">${severity}</span>`;
}

function refreshRecentAlerts() {
    const tbody = document.getElementById("recent-alerts-body");
    if (!tbody) return;

    fetch("/api/alerts/recent?limit=10")
        .then(r => r.json())
        .then(alerts => {
            if (alerts.length === 0) {
                tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">No alerts yet.</td></tr>';
                return;
            }
            tbody.innerHTML = alerts.map(a => `
                <tr>
                    <td class="small">${a.timestamp.slice(11, 19)}</td>
                    <td class="small">${a.alert_type}</td>
                    <td>${severityBadge(a.severity)}</td>
                    <td class="small">${a.asset || '—'}</td>
                </tr>
            `).join("");
        })
        .catch(err => console.warn("recent alerts fetch failed:", err));
}

// -- Master init and refresh loop --

function refreshAll() {
    refreshSummary();
    refreshAlertsTimeChart();
    refreshSeverityPie();
    refreshRiskPie();
    refreshRecentAlerts();
}

function initDashboard() {
    refreshAll();
    // refresh every 10 seconds so the dashboard reflects new events
    setInterval(refreshAll, 10000);
}
