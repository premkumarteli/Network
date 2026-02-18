const POLLING_INTERVAL = 5000; // Poll every 5 seconds

function fetchDevicesList() {
    fetch('/api/devices')
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok.');
            return response.json();
        })
        .then(devices => {
            const tableBody = document.getElementById('devicesList');
            tableBody.innerHTML = ''; // Clear existing rows

            devices.forEach(device => {
                const row = tableBody.insertRow();
                
                // IP (with link to user page)
                const ipCell = row.insertCell();
                const link = document.createElement('a');
                link.href = `/user/${device.ip}`;
                link.textContent = device.ip;
                link.classList.add('text-blue-400', 'hover:underline');
                ipCell.appendChild(link);

                // MAC
                row.insertCell().textContent = device.mac;
                
                // Hostname
                row.insertCell().textContent = device.hostname || 'Unknown'; 
                
                // Traffic MB
                const trafficCell = row.insertCell();
                trafficCell.textContent = device.traffic.toFixed(3);
                
                // VPN Flag
                const vpnCell = row.insertCell();
                vpnCell.textContent = device.vpn ? 'Yes' : 'No';
                vpnCell.classList.add(device.vpn ? 'text-red-400' : 'text-green-400');

                // Last Seen
                row.insertCell().textContent = formatLastSeen(device.last_seen);
            });
        })
        .catch(error => console.error('Error fetching device list:', error));
}

function formatLastSeen(timestamp) {
    // timestamp format is expected to be a string like "2025-11-20 00:00:00"
    try {
        const date = new Date(timestamp);
        return date.toLocaleTimeString() + ' ' + date.toLocaleDateString();
    } catch {
        return timestamp;
    }
}

// Minimal Chart initialization for this page (requires chart data polling)
let chartInstance = null;
function initializeDevicesChart() {
    const ctx = document.getElementById('devicesBandwidthChart').getContext('2d');
    chartInstance = new Chart(ctx, {
        type: 'line',
        data: { labels: ['Loading'], datasets: [{ data: [0], label: 'Total Traffic' }] },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: { x: { display: false }, y: { beginAtZero: true } },
            plugins: { legend: { display: false } }
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    initializeDevicesChart();
    fetchDevicesList();
    setInterval(fetchDevicesList, POLLING_INTERVAL);
    // You would also set up a separate function here to poll /api/admin/stats 
    // and update the chart, similar to the dashboard.js logic.
});