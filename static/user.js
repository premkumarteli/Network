const POLLING_INTERVAL = 5000; // Poll every 5 seconds
// userIp variable is defined in the HTML template's script block: <script>const userIp = "{{ user_ip }}";</script>

function fetchUserData() {
    fetch(`/api/user/${userIp}/activity`)
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok.');
            return response.json();
        })
        .then(data => {
            // 1. Update User Info Card
            const infoDiv = document.getElementById('userInfo');
            const device = data.device || { ip: userIp, mac: 'N/A', hostname: 'N/A', traffic: 0, vpn: false };

            infoDiv.innerHTML = `
                <p><strong>IP:</strong> ${device.ip}</p>
                <p><strong>MAC:</strong> ${device.mac}</p>
                <p><strong>Hostname:</strong> ${device.hostname || 'N/A'}</p>
                <p><strong>Traffic Total:</strong> ${device.traffic.toFixed(3)} MB</p>
                <p class="mt-2"><strong>VPN Status:</strong> 
                    <span class="${device.vpn ? 'text-red-400 font-bold' : 'text-green-400'}">
                        ${device.vpn ? 'ALERT (VPN/Suspicious)' : 'Normal'}
                    </span>
                </p>
            `;

            // 2. Populate Activity Logs Table
            const logsBody = document.getElementById('userLogs');
            logsBody.innerHTML = '';
            
            data.logs.forEach(log => {
                const row = logsBody.insertRow();
                row.insertCell().textContent = log.time;
                row.insertCell().textContent = log.domain || 'N/A';
                row.insertCell().textContent = log.protocol;
                row.insertCell().textContent = log.size;
            });
            
            // Log any VPN alerts specifically for this user
            if (data.vpn_alerts && data.vpn_alerts.length > 0) {
                 console.warn(`VPN Alerts for ${userIp}:`, data.vpn_alerts);
                 // Optional: Add alert message to the infoDiv for visibility
                 infoDiv.innerHTML += `<p class="text-red-400 mt-2">Active VPN Alerts: ${data.vpn_alerts.length}</p>`;
            }
        })
        .catch(error => {
            console.error('Error fetching user data:', error);
            document.getElementById('userInfo').textContent = `Error loading data for ${userIp}.`;
        });
}

document.addEventListener('DOMContentLoaded', () => {
    fetchUserData();
    setInterval(fetchUserData, POLLING_INTERVAL);
});