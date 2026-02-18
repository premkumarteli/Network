// Stats
function loadStats() {
  fetch("/api/stats")
    .then(r => r.json())
    .then(d => {
      deviceCount.innerText = d.devices;
      vpnCount.innerText = d.vpn_alerts;
      bandwidth.innerText = d.bandwidth + " MB";
    });
}
loadStats();
setInterval(loadStats, 2000);

// VPN alerts
function loadAlerts() {
  fetch("/api/vpn-alerts")
    .then(r => r.json())
    .then(data => {
      alertTable.innerHTML = data.map(
        a => `
        <tr class="border-b border-gray-800">
          <td class="py-2">${a.ip}</td>
          <td class="py-2 text-yellow-400">${a.reason}</td>
        </tr>`
      ).join("");
    });
}
loadAlerts();
setInterval(loadAlerts, 3000);

// Devices
function loadUsers() {
  fetch("/api/devices")
    .then(r => r.json())
    .then(data => {
      userTable.innerHTML = data.map(
        u => `
        <tr onclick="location.href='/user/${u.ip}'"
            class="cursor-pointer border-b border-gray-800 hover:bg-gray-800">
          <td class="py-2">${u.ip}</td>
          <td class="py-2">${u.mac}</td>
        </tr>`
      ).join("");
    });
}
loadUsers();
setInterval(loadUsers, 4000);
