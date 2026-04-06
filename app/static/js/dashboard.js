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
  const devices = document.getElementById("kpiTotalDevices");
  const vulns = document.getElementById("kpiTotalVulns");
  const critical = document.getElementById("kpiCriticalVulns");
  if (devices) devices.textContent = payload.total_devices;
  if (vulns) vulns.textContent = payload.total_vulnerabilities;
  if (critical) critical.textContent = payload.critical_vulnerabilities;
}

async function renderTopCriticalDevices() {
  const tbody = document.getElementById("topDevicesBody");
  if (!tbody) return;
  const payload = await fetch("/api/v1/dashboard/top-critical-devices").then((r) => r.json());
  if (!payload.items || payload.items.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="p-4 align-middle text-center text-muted-foreground">No device risk data available.</td></tr>';
    return;
  }
  tbody.innerHTML = payload.items
    .map(
      (item) =>
        `<tr class="border-b transition-colors hover:bg-muted/50">
          <td class="p-4 align-middle"><a href="/devices/${item.id}" class="font-medium hover:underline">${item.hostname}</a></td>
          <td class="p-4 align-middle">${item.department}</td>
          <td class="p-4 align-middle">${item.critical_vuln_count}</td>
          <td class="p-4 align-middle">${item.weighted_risk}</td>
          <td class="p-4 align-middle font-mono text-xs">${item.top_cve}</td>
        </tr>`
    )
    .join("");
}

// REAL SCANNER JAVASCRIPT

function loadNetworkInfo() {
  fetch("/api/v1/scan/network-info")
    .then(r => r.json())
    .then(data => {
      const localIp = document.getElementById("local-ip");
      const networkCidr = document.getElementById("network-cidr");
      const scanTarget = document.getElementById("scan-target");
      const nmapStatus = document.getElementById("nmap-status");
      const btnStart = document.getElementById("btn-start-scan");

      if (localIp) localIp.textContent = data.network.local_ip || "Unknown";
      if (networkCidr) networkCidr.textContent = data.network.network_cidr || "Unknown";
      if (scanTarget) {
        scanTarget.placeholder = data.network.network_cidr || "Enter CIDR";
        if (!scanTarget.value) scanTarget.value = data.network.network_cidr || "";
      }
      
      if (nmapStatus) {
        if (data.nmap.installed) {
          nmapStatus.innerHTML = `<span class="text-green-500 font-bold">✅ Installed</span> — ${data.nmap.version}`;
        } else {
          nmapStatus.innerHTML = `<span class="text-red-500 font-bold">❌ Not Installed</span> — Install with: <code>brew install nmap</code> or <code>sudo apt install nmap</code>`;
          if (btnStart) {
            btnStart.disabled = true;
            btnStart.classList.add("opacity-50", "cursor-not-allowed");
          }
        }
      }
    })
    .catch(() => {
      const localIp = document.getElementById("local-ip");
      if (localIp) localIp.textContent = "Error detecting";
    });
}

function startRealScan() {
  const target = document.getElementById("scan-target").value;
  const scanType = document.getElementById("scan-type").value;
  
  if (!target) {
    alert("Please enter a target network (e.g., 192.168.1.0/24)");
    return;
  }
  
  if (!confirm(`Start ${scanType} scan on ${target}?\n\nMake sure you have permission to scan this network.`)) {
    return;
  }
  
  fetch("/api/v1/scan/start", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ target: target, scan_type: scanType })
  })
  .then(r => r.json())
  .then(data => {
    if (data.error) {
      alert(data.error);
      return;
    }
    
    document.getElementById("scan-progress").classList.remove("hidden");
    document.getElementById("btn-start-scan").classList.add("hidden");
    document.getElementById("btn-stop-scan").classList.remove("hidden");
    document.getElementById("scan-results-summary").classList.add("hidden");
    
    pollScanStatus();
  })
  .catch(err => alert("Error starting scan: " + err));
}

function pollScanStatus() {
  const interval = setInterval(() => {
    fetch("/api/v1/scan/status")
      .then(r => r.json())
      .then(state => {
        const bar = document.getElementById("progress-bar");
        const msg = document.getElementById("scan-message");
        
        if (bar) {
          bar.style.width = state.progress + "%";
          bar.textContent = state.progress + "%";
        }
        if (msg) msg.textContent = state.message || "";
        
        if (state.status === "completed") {
          clearInterval(interval);
          document.getElementById("btn-start-scan").classList.remove("hidden");
          document.getElementById("btn-stop-scan").classList.add("hidden");
          if (bar) bar.classList.replace("bg-green-500", "bg-green-600");
          
          if (state.results) {
            document.getElementById("scan-results-summary").classList.remove("hidden");
            document.getElementById("result-hosts").textContent = state.results.total_hosts || 0;
            document.getElementById("result-ports").textContent = state.results.total_open_ports || 0;
          }
          
          setTimeout(() => location.reload(), 3000);
          
        } else if (state.status === "failed") {
          clearInterval(interval);
          document.getElementById("btn-start-scan").classList.remove("hidden");
          document.getElementById("btn-stop-scan").classList.add("hidden");
          if (bar) bar.classList.replace("bg-green-500", "bg-red-500");
          if (msg) msg.textContent = "Error: " + (state.error || "Unknown error");
        }
      })
      .catch(() => {});
  }, 2000);
}

document.addEventListener("DOMContentLoaded", () => {
  refreshDashboardSummary();
  renderDashboardCharts();
  renderTopCriticalDevices();
  loadNetworkInfo();
  
  // Check if a scan is already running on load
  fetch("/api/v1/scan/status")
    .then(r => r.json())
    .then(state => {
      if (state.status === "running") {
        document.getElementById("scan-progress").classList.remove("hidden");
        document.getElementById("btn-start-scan").classList.add("hidden");
        document.getElementById("btn-stop-scan").classList.remove("hidden");
        pollScanStatus();
      }
    });
});
