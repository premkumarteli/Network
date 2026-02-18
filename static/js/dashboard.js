async function apiGet(path) { const r = await fetch(path); return await r.json(); }
let trafficChart = null, protocolChart = null;

function initCharts() {
  // Traffic Chart
  const ctxTraffic = document.getElementById('trafficChart');
  if (ctxTraffic) {
    trafficChart = new Chart(ctxTraffic, {
      type: 'line',
      data: {
        labels: [],
        datasets: [{
          label: 'Total Traffic (MB)',
          data: [],
          borderColor: '#06b6d4', // Cyan
          backgroundColor: (context) => {
            const ctx = context.chart.ctx;
            const gradient = ctx.createLinearGradient(0, 0, 0, 400);
            gradient.addColorStop(0, 'rgba(6, 182, 212, 0.5)');
            gradient.addColorStop(1, 'rgba(6, 182, 212, 0)');
            return gradient;
          },
          borderWidth: 3,
          pointBackgroundColor: '#fff',
          pointBorderColor: '#06b6d4',
          pointRadius: 4,
          pointHoverRadius: 6,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: 'rgba(255, 255, 255, 0.05)' },
            ticks: { color: '#94a3b8' }
          },
          x: {
            grid: { display: false },
            ticks: { color: '#94a3b8' }
          }
        }
      }
    });
  }

  // Protocol Chart
  const ctxProtocol = document.getElementById('protocolChart');
  if (ctxProtocol) {
    protocolChart = new Chart(ctxProtocol, {
      type: 'doughnut',
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: ['#06b6d4', '#8b5cf6', '#ef4444', '#10b981', '#f59e0b'],
          borderColor: '#050505',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#fff' } } },
        cutout: '70%'
      }
    });
  }
}

async function refreshStats() {
  try {
    const s = await apiGet('/api/stats');

    const devCount = document.getElementById('active-devices');
    if (devCount) devCount.innerText = s.devices;

    const vpnCount = document.getElementById('vpn-alerts');
    if (vpnCount) vpnCount.innerText = s.vpn_alerts;

    const bw = document.getElementById('total-traffic');
    if (bw) bw.innerText = s.bandwidth;

    // Update speeds if available in API (assuming api/stats returns them, otherwise 0)
    const up = document.getElementById('upload-speed');
    if (up) up.innerText = s.upload_speed || 0;

    const down = document.getElementById('download-speed');
    if (down) down.innerText = s.download_speed || 0;

    // Update Traffic Chart
    if (trafficChart) {
      const now = new Date().toLocaleTimeString();
      trafficChart.data.labels.push(now);
      // Parse "123.45 MB" to float
      const val = parseFloat(s.bandwidth) || 0;
      trafficChart.data.datasets[0].data.push(val);

      if (trafficChart.data.labels.length > 20) {
        trafficChart.data.labels.shift();
        trafficChart.data.datasets[0].data.shift();
      }
      trafficChart.update();
    }

    // Update Protocol Chart (if exists)
    if (protocolChart && s.protocols) {
      protocolChart.data.labels = Object.keys(s.protocols);
      protocolChart.data.datasets[0].data = Object.values(s.protocols);
      protocolChart.update();
    }

  } catch (e) { console.error(e); }
}

async function refreshAlerts() {
  // handled in refreshStats for the counter
}

async function refreshDevices() {
  // handled in Devices.js
}

async function refreshActivity() {
  try {
    const a = await apiGet('/api/activity');
    const t = document.getElementById('activity-log-body');

    // Deduplicate by IP for the dashboard view (show only latest per device)
    const unique = [];
    const seen = new Set();
    for (const item of a) {
      if (!seen.has(item.ip)) {
        seen.add(item.ip);
        unique.push(item);
      }
      if (unique.length >= 5) break;
    }

    if (t) {
      if (unique.length === 0) {
        t.innerHTML = `
            <tr>
                <td colspan="5" style="text-align:center; padding: 2rem; color: var(--text-muted);">
                    <div style="margin-bottom: 0.5rem;">Listening for traffic...</div>
                    <small>Activity will appear here live.</small>
                </td>
            </tr>`;
      } else {
        t.innerHTML = unique.map(x => `
                <tr onclick="location.href='/user/${x.ip}'" style="cursor:pointer">
                    <td class="mono" style="color: var(--text-muted);">${x.time}</td>
                    <td>
                        <div class="mono" style="color: var(--primary);">${x.ip}</div>
                    </td>
                    <td>${x.domain || '-'}</td>
                    <td><span class="badge">${x.protocol || 'Unknown'}</span></td>
                    <td class="mono">${x.size}</td>
                </tr>`).join('');
      }
    }
  } catch (e) { console.error(e); }
}

// Global rename function
window.renameDevice = function (ip, mac, currentName) {
  const newName = prompt('Enter a friendly name for this device:', currentName);
  if (!newName || newName === currentName) return;

  fetch('/api/device/rename', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, mac: mac, name: newName })
  })
    .then(res => res.json())
    .then(data => {
      if (data.success) {
        // Optimistic update for immediate feedback
        const infoCard = document.getElementById('userInfo');
        if (infoCard) {
          const nameHeader = infoCard.querySelector('span[style*="font-size: 1.5rem"]');
          if (nameHeader) nameHeader.textContent = newName;
        }

        // Wait for DB worker to process the update before reloading
        setTimeout(refreshUserPage, 1000);
      } else {
        alert('Error: ' + (data.error || 'Failed to rename'));
      }
    })
    .catch(err => console.error(err));
};

let userDomainChart = null;

async function refreshUserPage() {
  if (typeof userIp === 'undefined') return;
  try {
    const u = await apiGet(`/api/user/${userIp}/activity`);
    const info = document.getElementById('userInfo');
    const logs = document.getElementById('userLogs');

    // Update User Info
    if (info) {
      if (u.device) {
        const lastSession = (u.sessions && u.sessions.length > 0) ? u.sessions[0] : null;
        const sessionStr = lastSession ? `${lastSession.start} — ${lastSession.end}` : 'No active sessions';

        info.innerHTML = `
            <div style="display: flex; flex-direction: column; gap: 1rem;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                    <div>
                        <div style="font-size: 1.5rem; font-weight: 700; color: var(--primary); letter-spacing: -0.5px;">${u.device.hostname || 'Unknown Device'}</div>
                        <div class="mono" style="color: var(--text-muted); font-size: 0.9rem;">${u.device.ip}</div>
                    </div>
                    <button class="action-btn" onclick="renameDevice('${u.device.ip}', '${u.device.mac}', '${u.device.hostname || ''}')" title="Rename Device">
                        <i class="ri-edit-line"></i>
                    </button>
                </div>
                
                <div style="display: grid; grid-template-columns: auto 1fr; gap: 0.75rem 2rem; font-size: 0.9rem; padding-top: 1rem; border-top: 1px solid var(--glass-border);">
                    <span style="color: var(--text-muted);">MAC Address</span>
                    <span class="mono">${u.device.mac}</span>
                    
                    <span style="color: var(--text-muted);">Total Traffic</span>
                    <span class="mono" style="color: var(--text-main);">${u.device.traffic.toFixed(3)} MB</span>
                    
                    <span style="color: var(--text-muted);">Status</span>
                    <span>${u.device.vpn ? '<span class="badge danger">VPN Detected</span>' : '<span class="badge success">Safe</span>'}</span>
                    
                    <span style="color: var(--text-muted);">Last Session</span>
                    <span class="mono" style="font-size: 0.8rem;">${sessionStr}</span>
                </div>
            </div>
          `;
      } else {
        info.innerHTML = '<div style="text-align:center; color: var(--danger);">Device not found</div>';
      }
    }

    // Update Domain Chart
    // Update Domain Chart
    const ctx = document.getElementById('userDomainChart');
    if (ctx) {
      const container = ctx.parentElement;
      // Create or select no-data message element
      let noDataMsg = container.querySelector('.no-data-msg');
      if (!noDataMsg) {
        noDataMsg = document.createElement('div');
        noDataMsg.className = 'no-data-msg';
        noDataMsg.style.cssText = 'display: flex; align-items: center; justify-content: center; height: 100%; color: #666; position: absolute; top: 0; left: 0; width: 100%;';
        noDataMsg.innerText = 'No browsing data available';
        container.style.position = 'relative'; // Ensure positioning context
        container.appendChild(noDataMsg);
      }

      if (u.domain_stats && Object.keys(u.domain_stats).length > 0) {
        // Has data: Show canvas, hide message
        ctx.style.display = 'block';
        noDataMsg.style.display = 'none';

        if (!userDomainChart) {
          userDomainChart = new Chart(ctx, {
            type: 'pie',
            data: { labels: [], datasets: [{ data: [], backgroundColor: ['#00f3ff', '#00ff9d', '#ff00ff', '#ffff00', '#ff0000'] }] },
            options: {
              responsive: true,
              maintainAspectRatio: false,
              plugins: { legend: { position: 'right', labels: { color: '#fff', font: { size: 10 } } } }
            }
          });
        }
        userDomainChart.data.labels = Object.keys(u.domain_stats);
        userDomainChart.data.datasets[0].data = Object.values(u.domain_stats);
        userDomainChart.update();
      } else {
        // No data: Hide canvas, show message
        ctx.style.display = 'none';
        noDataMsg.style.display = 'flex';
      }
    }

    // Update Logs
    if (logs) {
      const data = (u.sessions && u.sessions.length > 0) ? u.sessions : (u.logs || []);
      if (u.sessions && u.sessions.length > 0) {
        logs.innerHTML = u.sessions.map(l => `
                <tr>
                    <td class="mono" style="color: var(--text-muted); font-size: 0.85rem;">${l.start}<br>${l.end}</td>
                    <td>${l.domain}</td>
                    <td><span class="badge">${l.protocol || 'Session'}</span></td>
                    <td class="mono">-</td>
                </tr>`).join('');
      } else {
        logs.innerHTML = data.map(l => `
            <tr>
                <td class="mono" style="color: var(--text-muted);">${l.time}</td>
                <td>${l.domain}</td>
                <td><span class="badge">${l.protocol}</span></td>
                <td class="mono">${l.size}</td>
            </tr>`).join('');
      }
    }
  } catch (e) { console.error(e); }
}

function startPolling() {
  initCharts();
  refreshStats();
  refreshActivity(); // Initial load

  // Polling for stats (aggregated data)
  setInterval(refreshStats, 3000);
  setInterval(refreshUserPage, 4000);

  // Real-time Packets via WebSockets
  const socket = io();

  socket.on('connect', () => {
    console.log("[WS] Connected to server");
  });

  socket.on('packet_event', (pkt) => {
    const t = document.getElementById('activity-log-body');
    if (!t) return;

    // Create new row
    const row = document.createElement('tr');
    row.onclick = () => location.href = '/user/' + pkt.src_ip;
    row.style.cursor = 'pointer';
    row.className = 'packet-row'; // Add CSS class for animation if desired

    row.innerHTML = `
        <td class="mono" style="color: var(--text-muted);">${pkt.time_str.split(' ')[1]}</td>
        <td><div class="mono" style="color: var(--primary);">${pkt.src_ip}</div></td>
        <td>${pkt.domain || '-'}</td>
        <td><span class="badge">${pkt.protocol || 'Unknown'}</span></td>
        <td class="mono">${pkt.size}</td>
    `;

    // Prepend and limit to 15 rows
    t.insertBefore(row, t.firstChild);
    while (t.children.length > 15) {
      t.removeChild(t.lastChild);
    }
  });
}
document.addEventListener('DOMContentLoaded', startPolling);