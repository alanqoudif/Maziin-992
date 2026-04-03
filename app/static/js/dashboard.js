async function renderDashboardCharts() {
  const severityCanvas = document.getElementById("severityChart");
  const deptCanvas = document.getElementById("departmentChart");
  const trendCanvas = document.getElementById("trendChart");
  if (!severityCanvas || !deptCanvas || !trendCanvas) return;

  const severityData = await fetch("/api/v1/charts/severity_distribution").then((r) => r.json());
  const deptData = await fetch("/api/v1/charts/department_vulns").then((r) => r.json());
  const trendData = await fetch("/api/v1/charts/trend").then((r) => r.json());

  new Chart(severityCanvas, {
    type: "doughnut",
    data: { labels: severityData.labels, datasets: [{ data: severityData.values }] },
    options: { plugins: { legend: { labels: { color: "#dce7ff" } } } }
  });
  new Chart(deptCanvas, {
    type: "bar",
    data: { labels: deptData.labels, datasets: [{ label: "Vulns", data: deptData.values, backgroundColor: "#4ea7ff" }] },
    options: {
      scales: {
        x: { ticks: { color: "#dce7ff" }, grid: { color: "rgba(156,176,216,0.15)" } },
        y: { ticks: { color: "#dce7ff" }, grid: { color: "rgba(156,176,216,0.15)" } }
      },
      plugins: { legend: { labels: { color: "#dce7ff" } } }
    }
  });
  new Chart(trendCanvas, {
    type: "line",
    data: {
      labels: trendData.labels,
      datasets: [{ label: "Discovered Vulnerabilities", data: trendData.values, borderColor: "#34d399", backgroundColor: "rgba(52,211,153,0.25)", tension: 0.25, fill: true }]
    },
    options: {
      scales: {
        x: { ticks: { color: "#dce7ff", maxRotation: 45, minRotation: 45 }, grid: { color: "rgba(156,176,216,0.1)" } },
        y: { ticks: { color: "#dce7ff" }, grid: { color: "rgba(156,176,216,0.15)" } }
      },
      plugins: { legend: { labels: { color: "#dce7ff" } } }
    }
  });
}

async function refreshDashboardSummary() {
  const payload = await fetch("/api/v1/dashboard/stats").then((r) => r.json());
  const patch = document.getElementById("kpiPatchCompliance");
  const devices = document.getElementById("kpiTotalDevices");
  const vulns = document.getElementById("kpiTotalVulns");
  const critical = document.getElementById("kpiCriticalVulns");
  if (patch) patch.textContent = `${payload.patch_compliance_percent}%`;
  if (devices) devices.textContent = payload.total_devices;
  if (vulns) vulns.textContent = payload.total_vulnerabilities;
  if (critical) critical.textContent = payload.critical_vulnerabilities;
}

async function renderTopCriticalDevices() {
  const tbody = document.getElementById("topDevicesBody");
  if (!tbody) return;
  const payload = await fetch("/api/v1/dashboard/top-critical-devices").then((r) => r.json());
  if (!payload.items || payload.items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5">No device risk data available.</td></tr>';
    return;
  }
  tbody.innerHTML = payload.items
    .map(
      (item) =>
        `<tr>
          <td><a href="/devices/${item.id}">${item.hostname}</a></td>
          <td>${item.department}</td>
          <td>${item.critical_vuln_count}</td>
          <td>${item.weighted_risk}</td>
          <td>${item.top_cve}</td>
        </tr>`
    )
    .join("");
}

async function renderRecentAlerts() {
  const list = document.getElementById("recentAlertsList");
  if (!list) return;
  const payload = await fetch("/api/v1/dashboard/recent-alerts").then((r) => r.json());
  if (!payload.items || payload.items.length === 0) {
    list.innerHTML = "<li>No alerts yet.</li>";
    return;
  }
  list.innerHTML = payload.items
    .map((item) => {
      const ts = new Date(item.created_at).toLocaleString();
      return `<li>[${item.type}] ${item.severity.toUpperCase()} - ${item.device} - ${item.message} <span class="text-muted">(${ts})</span></li>`;
    })
    .join("");
}

async function triggerRealScan() {
  const messageNode = document.getElementById("scanMessage");
  try {
    const response = await fetch("/api/v1/scan/trigger", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ real: true })
    });
    const payload = await response.json();
    messageNode.textContent = payload.message || payload.status;
  } catch (err) {
    messageNode.textContent = `Failed to trigger scan: ${err}`;
  }
}

async function refreshScanStatus() {
  const statusNode = document.getElementById("scanStatusText");
  if (!statusNode) return;
  const payload = await fetch("/api/v1/scan/status").then((r) => r.json());
  statusNode.textContent = payload.status;
  statusNode.className = `badge status-${payload.status}`;
  document.getElementById("scanDuration").textContent = payload.duration_sec || 0;
  document.getElementById("scanHosts").textContent = payload.discovered_hosts || 0;
  document.getElementById("scanPorts").textContent = payload.open_ports_count || 0;
  const err = document.getElementById("scanErrorText");
  err.textContent = payload.error ? `Last error: ${payload.error}` : "";
  if (payload.status === "failed" || payload.status === "idle") {
    await triggerRealScan();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshDashboardSummary();
  renderDashboardCharts();
  renderTopCriticalDevices();
  renderRecentAlerts();
  setInterval(refreshScanStatus, 5000);
  refreshScanStatus();
});
