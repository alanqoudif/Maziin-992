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

  // Attack Activity tabs — init first tab
  initAttackTabs();
});

// ─────────────────────────────────────────────────────────────────────────────
//  ATTACK ACTIVITY TABS
// ─────────────────────────────────────────────────────────────────────────────

let _attackMap = null;           // Leaflet instance
let _timelineChart = null;       // Chart.js stacked line
let _typeChart = null;           // Chart.js doughnut
let _activeAttackTab = "map";
let _attackRefreshTimer = null;

function initAttackTabs() {
  if (!document.getElementById("attack-tab-map")) return;
  renderAttackMap();
  // Auto-refresh every 30 seconds
  _attackRefreshTimer = setInterval(() => {
    refreshActiveAttackTab();
  }, 30000);
}

function switchAttackTab(tab) {
  _activeAttackTab = tab;
  // Toggle panel visibility
  ["map", "killchain", "timeline"].forEach(t => {
    const panel = document.getElementById("attack-tab-" + t);
    if (panel) panel.classList.toggle("hidden", t !== tab);
  });
  // Update tab button styles
  document.querySelectorAll(".attack-tab").forEach(btn => {
    const isActive = btn.dataset.tab === tab;
    btn.classList.toggle("bg-accent", isActive);
    btn.classList.toggle("text-accent-foreground", isActive);
    btn.classList.toggle("text-muted-foreground", !isActive);
    btn.classList.toggle("hover:text-foreground", !isActive);
  });
  // Lazy-load tab content
  if (tab === "map") renderAttackMap();
  if (tab === "killchain") renderKillChain();
  if (tab === "timeline") renderAttackTimeline();
}

function refreshActiveAttackTab() {
  if (_activeAttackTab === "map") renderAttackMap();
  if (_activeAttackTab === "killchain") renderKillChain();
  if (_activeAttackTab === "timeline") renderAttackTimeline();
}

// ── Tab A: Geo Map ────────────────────────────────────────────────────────────

async function renderAttackMap() {
  if (!document.getElementById("attack-map")) return;

  const data = await fetch("/api/v1/attacks/geo").then(r => r.json()).catch(() => []);

  // Initialise Leaflet on first load
  if (!_attackMap) {
    _attackMap = L.map("attack-map", {
      center: [20, 10],
      zoom: 2,
      zoomControl: true,
      attributionControl: false,
    });
    L.tileLayer("https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png", {
      attribution: "&copy; CartoDB",
      subdomains: "abcd",
      maxZoom: 10,
    }).addTo(_attackMap);
  } else {
    // Clear existing circles
    _attackMap.eachLayer(layer => {
      if (layer instanceof L.CircleMarker) _attackMap.removeLayer(layer);
    });
  }

  if (!data.length) return;
  const maxCount = Math.max(...data.map(d => d.count), 1);

  data.forEach(d => {
    const radius = 8 + (d.count / maxCount) * 22;
    L.circleMarker([d.lat, d.lng], {
      radius,
      color: "#ef4444",
      fillColor: "#ef4444",
      fillOpacity: 0.55,
      weight: 1,
    })
      .bindPopup(
        `<b>${d.country_name}</b><br/>
         Events: <b>${d.count}</b><br/>
         Top type: ${d.top_event_type}`
      )
      .addTo(_attackMap);
  });
}

// ── Tab B: MITRE Kill Chain Heatmap ──────────────────────────────────────────

async function renderKillChain() {
  const container = document.getElementById("killchain-grid");
  if (!container) return;

  const data = await fetch("/api/v1/attacks/killchain").then(r => r.json()).catch(() => []);
  if (!data.length) {
    container.innerHTML = '<p class="text-xs text-muted-foreground">No data.</p>';
    return;
  }

  const maxCount = Math.max(...data.map(d => d.count), 1);

  container.innerHTML = data.map(d => {
    const intensity = maxCount > 0 ? d.count / maxCount : 0;
    const sev = d.severity_breakdown || {};
    const hasCritHigh = (sev.critical || 0) + (sev.high || 0) > 0;
    const hasMed = (sev.medium || 0) > 0;

    let bgColor;
    if (d.count === 0) {
      bgColor = "rgba(255,255,255,0.05)";
    } else if (hasCritHigh) {
      bgColor = `rgba(239,68,68,${0.2 + intensity * 0.65})`;
    } else if (hasMed) {
      bgColor = `rgba(234,179,8,${0.2 + intensity * 0.65})`;
    } else {
      bgColor = `rgba(59,130,246,${0.2 + intensity * 0.6})`;
    }

    const shortName = d.tactic.replace("Command and Control", "C2").replace("Privilege Escalation", "Priv. Esc.").replace("Defense Evasion", "Def. Evasion");
    const critHigh = (sev.critical || 0) + (sev.high || 0);
    const SIEM_URL = `/siem-logs?q=event_type%3D"${encodeURIComponent(d.tactic)}"`;

    return `
      <a href="${SIEM_URL}" target="_blank"
         class="flex-shrink-0 flex flex-col items-center justify-between rounded-lg p-3 transition-transform hover:scale-105 cursor-pointer"
         style="background:${bgColor};min-width:80px;max-width:90px;min-height:100px;"
         title="${d.tactic}: ${d.count} events">
        <p class="text-[9px] text-center font-bold text-foreground/80 leading-tight">${shortName}</p>
        <p class="text-2xl font-bold text-foreground mt-2">${d.count}</p>
        ${critHigh > 0 ? `<p class="text-[9px] text-red-400 font-bold mt-1">${critHigh} crit/high</p>` : '<p class="text-[9px] text-muted-foreground mt-1">—</p>'}
      </a>
    `;
  }).join("");
}

// ── Tab C: Timeline + Type doughnut + recent table ───────────────────────────

const SEV_COLORS = {
  critical: "rgba(239,68,68,0.85)",
  high:     "rgba(249,115,22,0.75)",
  medium:   "rgba(234,179,8,0.7)",
  low:      "rgba(34,197,94,0.55)",
  info:     "rgba(99,102,241,0.45)",
};

async function renderAttackTimeline() {
  // Timeline chart
  const tlData = await fetch("/api/v1/attacks/timeline").then(r => r.json()).catch(() => null);
  if (tlData) {
    const tlCanvas = document.getElementById("attackTimelineChart");
    if (tlCanvas) {
      const sev_order = ["critical", "high", "medium", "low", "info"];
      const datasets = sev_order.map(s => ({
        label: s.charAt(0).toUpperCase() + s.slice(1),
        data: tlData.datasets[s] || [],
        backgroundColor: SEV_COLORS[s],
        borderColor: SEV_COLORS[s],
        borderWidth: 1,
        fill: true,
      }));
      if (_timelineChart) {
        _timelineChart.data.labels = tlData.labels;
        _timelineChart.data.datasets = datasets;
        _timelineChart.update();
      } else {
        _timelineChart = new Chart(tlCanvas, {
          type: "bar",
          data: { labels: tlData.labels, datasets },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
              x: { stacked: true, ticks: { color: "#dce7ff", maxRotation: 45, font: { size: 9 } }, grid: { color: "rgba(156,176,216,0.1)" } },
              y: { stacked: true, ticks: { color: "#dce7ff" }, grid: { color: "rgba(156,176,216,0.15)" } },
            },
            plugins: { legend: { labels: { color: "#dce7ff", boxWidth: 10, font: { size: 10 } } } },
          },
        });
      }
    }
  }

  // Type doughnut via severity aggregation
  const recentData = await fetch("/api/v1/attacks/recent").then(r => r.json()).catch(() => []);
  if (recentData.length) {
    const typeCounts = {};
    recentData.forEach(e => { typeCounts[e.event_type] = (typeCounts[e.event_type] || 0) + 1; });
    const topTypes = Object.entries(typeCounts).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const typeCanvas = document.getElementById("attackTypeChart");
    if (typeCanvas) {
      if (_typeChart) {
        _typeChart.data.labels = topTypes.map(t => t[0]);
        _typeChart.data.datasets[0].data = topTypes.map(t => t[1]);
        _typeChart.update();
      } else {
        _typeChart = new Chart(typeCanvas, {
          type: "doughnut",
          data: {
            labels: topTypes.map(t => t[0]),
            datasets: [{
              data: topTypes.map(t => t[1]),
              backgroundColor: ["#ef4444","#f97316","#eab308","#22c55e","#6366f1","#06b6d4"],
            }],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: "#dce7ff", boxWidth: 10, font: { size: 9 } } } },
          },
        });
      }
    }

    // Recent attacks table
    const tbody = document.getElementById("recent-attacks-tbody");
    if (tbody) {
      const sevBadge = (sev) => {
        const cls = ["critical","high"].includes(sev)
          ? "bg-red-900/40 text-red-400"
          : sev === "medium" ? "bg-yellow-900/40 text-yellow-400"
          : "bg-green-900/40 text-green-400";
        return `<span class="px-1.5 py-0.5 rounded font-bold text-[10px] ${cls}">${sev.toUpperCase()}</span>`;
      };
      tbody.innerHTML = recentData.map(e => `
        <tr class="border-b hover:bg-muted/20 transition-colors">
          <td class="py-2 px-2 font-mono text-muted-foreground text-[10px]">${e.ts.slice(11)}</td>
          <td class="py-2 px-2 font-mono">${e.src_ip}</td>
          <td class="py-2 px-2">${e.src_country}</td>
          <td class="py-2 px-2 font-mono">${e.dst_host !== "—" ? e.dst_host : e.dst_ip}</td>
          <td class="py-2 px-2">${e.event_type}</td>
          <td class="py-2 px-2">${sevBadge(e.severity)}</td>
        </tr>
      `).join("");
    }
  }
}
