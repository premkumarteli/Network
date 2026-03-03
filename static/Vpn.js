const POLLING_INTERVAL = 5000; // Poll every 5 seconds

function fetchVpnAlerts() {
    fetch('/api/vpn-alerts')
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok.');
            return response.json();
        })
        .then(alerts => {
            const list = document.getElementById('vpnList');
            list.innerHTML = ''; // Clear existing list
            
            if (alerts.length === 0) {
                const item = document.createElement('li');
                item.textContent = 'No VPN or suspicious activity alerts detected.';
                item.classList.add('p-2', 'text-green-400');
                list.appendChild(item);
                return;
            }

            alerts.forEach(alert => {
                const item = document.createElement('li');
                // Format: [Time] IP Reason
                item.innerHTML = `
                    <span class="font-mono text-gray-500">${alert.time}</span> &mdash;
                    <a href="/user/${alert.ip}" class="text-red-400 hover:underline font-semibold">${alert.ip}</a> &mdash; 
                    ${alert.reason}
                `;
                item.classList.add('p-2', 'border-b', 'border-red-900/50');
                list.appendChild(item);
            });
        })
        .catch(error => console.error('Error fetching VPN alerts:', error));
}

document.addEventListener('DOMContentLoaded', () => {
    fetchVpnAlerts();
    setInterval(fetchVpnAlerts, POLLING_INTERVAL);
});