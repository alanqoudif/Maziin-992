async function loadUnreadAlerts() {
  const data = await fetch("/api/v1/alerts?unread=true").then((r) => r.json());
  console.log("Unread alerts:", data.total);
}
document.addEventListener("DOMContentLoaded", loadUnreadAlerts);
