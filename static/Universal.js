document.addEventListener('DOMContentLoaded', () => {
    console.log("NetVisor JS Loaded");

    // ==========================================
    // 1. GLOBAL SIDEBAR LOGIC
    // ==========================================
    const sidebar = document.getElementById("sidebar");
    const toggleBtn = document.getElementById("toggleBtn");
    
    if (sidebar && toggleBtn) {
        toggleBtn.onclick = () => {
            sidebar.classList.toggle("collapsed");
        };
    }

    // Highlight Active Link
    const path = window.location.pathname;
    document.querySelectorAll('.navlink').forEach(link => {
        if(link.getAttribute('href') === path) {
            link.classList.add('active');
        }
    });

    // ==========================================
    // 2. PAGE ROUTING (Run logic based on page)
    // ==========================================
    
    // DASHBOARD PAGE
    if (document.getElementById('bandwidthChart')) {
        initDashboard();
    }

    // DEVICES PAGE
    if (document.getElementById('devicesList')) {
        initDevicesPage();
    }

    // ACTIVITY PAGE
    if (document.getElementById('activityList')) {
        initActivityPage();
    }

    // VPN PAGE
    if (document.getElementById('vpnList')) {
        initVpnPage();
    }

    // USER DETAIL PAGE
    if (document.getElementById('userIp')) {
        initUserPage();
    }

    // SETTINGS PAGE
    if (document.getElementById('tsharkPath')) {
        initSettingsPage();
    }
    
    // ADMIN PAGE
    if (document.getElementById('adminInfo')) {
        initAdminPage();
    }
});

// ==========================================
// DASHBOARD FUNCTIONS
// ==========================================
function initDashboard() {
    console.log("Initializing Dashboard...");

    const ctx = document.getElementById('bandwidthChart').getContext('2d');
    const bandwidthChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Traffic (MB)',
                data: [],
                borderColor: '#4ade80',
                backgroundColor: 'rgba(74, 222, 128, 0.1)',
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { x: { display: false }, y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });

    function updateDashboard() {
        // 1. Stats & Chart
        fetch('/api/stats').then(r => r.json()).then(d => {
            document.getElementById('deviceCount').innerText = d.devices;
            document.getElementById('vpnCount').innerText = d.vpn_alerts;
            document.getElementById('bandwidth').innerText = d.bandwidth.toFixed(2) + " MB";

            const now = new Date().toLocaleTimeString();
            if (bandwidthChart.data.labels.length > 20) {
                bandwidthChart.data.labels.shift();
                bandwidthChart.data.datasets[0].data.shift();
            }
            bandwidthChart.data.labels.push(now);
            bandwidthChart.data.datasets[0].data.push(d.bandwidth);
            bandwidthChart.update();
        }).catch(e => console.error(e));

        // 2. Mini Tables
        fetch('/api/vpn-alerts').then(r => r.json()).then(d => {
            document.getElementById('alertTable').innerHTML = d.slice(0, 5).map(a => 
                `<tr class="border-b border-gray-800"><td class="py-2 text-red-400">${a.ip}</td><td class="py-2 text-yellow-400 text-xs">${a.reason}</td></tr>`
            ).join('');
        });

        fetch('/api/devices').then(r => r.json()).then(d => {
            // Note: matching HTML id 'recentDevices'
            document.getElementById('recentDevices').innerHTML = d.slice(0, 5).map(u => 
                `<tr class="border-b border-gray-800 hover:bg-gray-800 cursor-pointer" onclick="location.href='/user/${u.ip}'">
                    <td class="py-2 text-blue-400">${u.ip}</td>
                    <td class="py-2 text-gray-500 text-xs">${u.mac}</td>
                    <td class="py-2 text-gray-300">${u.hostname || '-'}</td>
                    <td class="py-2 text-green-400 font-mono">${u.traffic.toFixed(2)}</td>
                </tr>`
            ).join('');
        });
    }
    setInterval(updateDashboard, 2000);
    updateDashboard();
}

// ==========================================
// DEVICES PAGE FUNCTIONS
// ==========================================
function initDevicesPage() {
    console.log("Initializing Devices List...");
    
    // Optional: Specific chart for devices page
    if(document.getElementById('devicesBandwidthChart')) {
        // You can initialize a second chart here if you want
    }

    function updateDevices() {
        fetch('/api/devices').then(r => r.json()).then(data => {
            // Note: matching HTML id 'devicesList'
            const tbody = document.getElementById('devicesList');
            if(!tbody) return;
            
            tbody.innerHTML = data.map(u => `
                <tr class="border-b border-gray-800 hover:bg-gray-800 transition cursor-pointer" onclick="location.href='/user/${u.ip}'">
                    <td class="py-3 text-blue-400 font-bold">${u.ip}</td>
                    <td class="py-3 text-gray-400 font-mono text-sm">${u.mac}</td>
                    <td class="py-3 text-white">${u.hostname || 'Unknown'}</td>
                    <td class="py-3 text-green-400 font-mono">${u.traffic.toFixed(2)} MB</td>
                    <td class="py-3">${u.vpn ? '<span class="text-red-400 font-bold">VPN</span>' : '<span class="text-green-400">Normal</span>'}</td>
                </tr>
            `).join('');
        }).catch(e => console.error("Device load error", e));
    }
    setInterval(updateDevices, 3000);
    updateDevices();
}

// ==========================================
// ACTIVITY PAGE FUNCTIONS
// ==========================================
function initActivityPage() {
    function updateActivity() {
        fetch('/api/activity').then(r => r.json()).then(data => {
            const tbody = document.getElementById('activityList');
            if(!data.length) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-gray-500">No activity yet</td></tr>';
                return;
            }
            tbody.innerHTML = data.map(log => `
                <tr class="border-b border-gray-800 text-xs hover:bg-gray-800">
                    <td class="py-2 text-gray-500">${log.time}</td>
                    <td class="py-2 text-blue-300">${log.ip}</td>
                    <td class="py-2 text-white">${log.domain || '-'}</td>
                    <td class="py-2 text-yellow-400">${log.protocol}</td>
                    <td class="py-2 text-gray-400">${log.size}</td>
                </tr>
            `).join('');
        });
    }
    setInterval(updateActivity, 2000);
    updateActivity();
}

// ==========================================
// VPN PAGE FUNCTIONS
// ==========================================
function initVpnPage() {
    function loadVpn() {
        fetch('/api/vpn-alerts').then(r => r.json()).then(list => {
            const ul = document.getElementById("vpnList"); // Use this ID in vpn.html
            // If you used a table in vpn.html, adjust this logic.
            // Assuming list layout based on your JS:
            if (!list || list.length === 0) {
                ul.innerHTML = `<div class="text-gray-500 p-4">No VPN alerts detected</div>`;
                return;
            }
            ul.innerHTML = list.map(v => `
                <li class="p-3 bg-gray-800 rounded border border-gray-700 hover:bg-gray-700 transition mb-2 list-none">
                    <div class="flex justify-between items-baseline">
                        <div class="text-yellow-300 font-semibold">${v.ip}</div>
                        <div class="text-xs text-gray-400">${v.time || ''}</div>
                    </div>
                    <div class="text-sm text-gray-300 mt-1">${v.reason}</div>
                </li>`).join("");
        });
    }
    setInterval(loadVpn, 4000);
    loadVpn();
}

// ==========================================
// USER DETAILS PAGE FUNCTIONS
// ==========================================
function initUserPage() {
    const ip = window.location.pathname.split("/").pop();
    const ipDisplay = document.getElementById("userIp");
    if(ipDisplay) ipDisplay.innerText = ip;

    function loadUser() {
        fetch(`/api/user/${ip}/activity`).then(r => r.json()).then(data => {
            // 1. Device Info
            const devDiv = document.getElementById('deviceDetails');
            if (devDiv && data.device) {
                devDiv.innerHTML = `
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div class="text-gray-400">MAC Address:</div><div>${data.device.mac}</div>
                        <div class="text-gray-400">Hostname:</div><div>${data.device.hostname}</div>
                        <div class="text-gray-400">Total Traffic:</div><div class="text-green-400">${data.device.traffic} MB</div>
                        <div class="text-gray-400">Risk Status:</div><div>${data.device.vpn ? '<span class="text-red-400">High (VPN)</span>' : '<span class="text-green-400">Normal</span>'}</div>
                    </div>
                `;
            }

            // 2. Sessions
            const sessDiv = document.getElementById('sessionList');
            if (sessDiv && data.sessions) {
                sessDiv.innerHTML = data.sessions.length ? data.sessions.map(s => `
                    <div class="p-2 bg-gray-800 mb-2 rounded border border-gray-700 text-sm">
                        <span class="text-blue-300 font-bold">${s.domain}</span>
                        <div class="text-xs text-gray-500">${s.start} - ${s.end || 'Active'}</div>
                    </div>
                `).join('') : '<div class="text-gray-500">No active sessions</div>';
            }

            // 3. Logs
            const logTable = document.getElementById('logTable'); // Ensure ID matches user.html
            if (logTable && data.logs) {
                logTable.innerHTML = data.logs.map(l => `
                    <tr class="border-b border-gray-800 hover:bg-gray-800">
                        <td class="py-2 text-xs text-gray-500">${l.time}</td>
                        <td class="py-2 text-sm text-white">${l.domain}</td>
                        <td class="py-2 text-xs text-yellow-400">${l.protocol}</td>
                    </tr>
                `).join('');
            }
        });
    }
    loadUser();
}

// ==========================================
// ADMIN PAGE FUNCTIONS
// ==========================================
function initAdminPage() {
    function updateAdmin() {
        fetch('/api/admin/stats').then(r => r.json()).then(d => {
            document.getElementById('adminInfo').innerHTML = `
                <div class="space-y-2">
                    <div class="flex justify-between"><span class="text-gray-400">Hostname:</span> <span>${d.hostname}</span></div>
                    <div class="flex justify-between"><span class="text-gray-400">Local IP:</span> <span>${d.local_ip}</span></div>
                    <div class="flex justify-between"><span class="text-gray-400">CPU Usage:</span> <span>${d.cpu_percent}%</span></div>
                    <div class="flex justify-between"><span class="text-gray-400">RAM Usage:</span> <span>${d.mem_used_mb} / ${d.mem_total_mb} MB</span></div>
                </div>
            `;
            document.getElementById('adminSpeeds').innerHTML = `
                <div class="grid grid-cols-2 gap-4 text-center">
                    <div class="bg-gray-800 p-3 rounded border border-gray-700">
                        <div class="text-xs text-gray-500">UPLOAD</div>
                        <div class="text-xl text-blue-400 font-mono">${d.upload_kbps} KB/s</div>
                    </div>
                    <div class="bg-gray-800 p-3 rounded border border-gray-700">
                        <div class="text-xs text-gray-500">DOWNLOAD</div>
                        <div class="text-xl text-green-400 font-mono">${d.download_kbps} KB/s</div>
                    </div>
                </div>
            `;
        });
    }
    setInterval(updateAdmin, 2000);
    updateAdmin();
}

// ==========================================
// SETTINGS PAGE FUNCTIONS
// ==========================================
function initSettingsPage() {
    // Currently only shows TShark path, logic can be expanded here
    console.log("Settings page loaded.");
}