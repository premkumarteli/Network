let isFetching = false;

async function refreshDevices() {
    if (isFetching) return;
    isFetching = true;

    try {
        const res = await fetch('/api/devices');
        const devices = await res.json();

        const tbody = document.getElementById('devicesList');
        if (tbody) {
            if (devices.length === 0) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="7" style="text-align:center; padding: 3rem; color: var(--text-muted);">
                            <i class="ri-loader-4-line spinning" style="font-size: 2rem; display: block; margin-bottom: 1rem;"></i>
                            <div>Scanner is initializing...</div>
                            <small>Waiting for network traffic. Ensure device is connected.</small>
                        </td>
                    </tr>`;
            } else {
                tbody.innerHTML = devices.map(d => {
                    let typeIcon = 'ri-question-line';
                    if (d.type === 'Mobile') typeIcon = 'ri-smartphone-line';
                    else if (d.type === 'Desktop') typeIcon = 'ri-computer-line';
                    else if (d.type === 'IoT') typeIcon = 'ri-cpu-line';
                    else if (d.type === 'Network') typeIcon = 'ri-router-line';

                    // Aggressive Offline Styling
                    const rowClass = d.is_online ? '' : 'style="opacity: 0.5; filter: grayscale(100%); border-left: 3px solid var(--danger); background: rgba(239, 68, 68, 0.05);"';
                    const ipStyle = d.is_online ? '' : 'color: var(--danger); text-decoration: line-through;';

                    // Click handler - only navigate if online or explicitly clicked (users complained about accidental clicks)
                    // We'll keep row click but ensure buttons stop propagation

                    return `
                    <tr onclick="location.href='/user/${d.ip}'" style="cursor:pointer" ${d.is_online ? '' : 'class="offline-row"'} ${rowClass}>
                        <td class="mono" style="${ipStyle}">${d.ip}</td>
                        <td class="mono" style="font-size: 0.85rem;">${d.mac || '-'}</td>
                        <td>
                            <div style="font-weight: 600; color: ${d.is_online ? 'var(--primary)' : 'var(--text-muted)'};">${d.hostname || 'Unknown'}</div>
                            ${(d.type || d.brand || d.os) ? `
                            <div style="font-size: 0.8rem; color: var(--text-muted); display: flex; gap: 0.5rem; align-items: center;">
                                ${d.type ? `<span><i class="${typeIcon}"></i> ${d.type}</span>` : ''}
                                ${(d.type && (d.brand || d.os)) ? '<span>•</span>' : ''}
                                ${d.brand ? `<span>${d.brand}</span>` : ''}
                                ${(d.brand && d.os) ? '<span>•</span>' : ''}
                                ${d.os ? `<span>${d.os}</span>` : ''}
                            </div>` : '<div style="font-size: 0.8rem; color: var(--text-muted); opacity: 0.5;">Detailed info unavailable</div>'}
                        </td>
                        </td>
                        <td class="mono">${d.traffic ? d.traffic.toFixed(2) : 0} MB</td>
                        <td>${d.is_online ? '<span class="badge success">Online</span>' : '<span class="badge danger">Offline</span>'}</td>
                        <td class="mono" style="font-size: 0.85rem;">${new Date(d.last_seen).toLocaleTimeString()}</td>
                        <td>
                            <button class="action-btn" onclick="event.stopPropagation(); renameDevice('${d.ip}', '${d.mac}', '${d.hostname || ''}')" title="Rename">
                                <i class="ri-edit-line"></i>
                            </button>
                        </td>
                    </tr>
                `}).join('');
            }
        }
    } catch (e) {
        console.error("Error fetching devices:", e);
    } finally {
        isFetching = false;
    }
}

// Reuse rename logic from Dashboard.js or define here if needed. 
// Since Dashboard.js is loaded in dashboard, but not here, we should probably duplicate or move to Universal.js.
// For now, I'll add it here to be safe.

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
                refreshDevices();
            } else {
                alert('Error: ' + (data.error || 'Failed to rename'));
            }
        })
        .catch(err => console.error(err));
};


// Socket.IO Connection
const socket = io();

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    refreshDevices();
});

// Update traffic on packet event
socket.on('packet_event', (pkt) => {
    // Find row
    // IDs are not on TR, so we query by IP in cell
    // Ideally we should add ID to TR using device IP
    // For now, let's look up by text content (slow) or add IDs in refreshDevices

    // Better: Update UI directly if row exists
    const rows = document.querySelectorAll('#devicesList tr');
    let found = false;

    rows.forEach(row => {
        const ipCell = row.cells[0];
        if (ipCell && ipCell.innerText.trim() === pkt.src_ip) {
            found = true;

            // Update Traffic
            const trafficCell = row.cells[3]; // 4th column
            if (trafficCell) {
                // Parse current MB
                let current = parseFloat(trafficCell.innerText);
                if (isNaN(current)) current = 0;

                // Add new packet (pkt.size is bytes)
                const addedMb = pkt.size / (1024 * 1024);
                const newTotal = current + addedMb;
                trafficCell.innerText = newTotal.toFixed(2) + ' MB';
            }

            // Mark Online if was offline (check class)
            if (row.classList.contains('offline-row')) {
                row.classList.remove('offline-row');
                row.style.opacity = '1';
                row.style.filter = 'none';
                row.style.borderLeft = 'none';
                row.style.background = 'none';

                // Update Status Badge
                const statusCell = row.cells[4];
                if (statusCell) {
                    statusCell.innerHTML = '<span class="badge success">Online</span>';
                }

                // Update Last Seen
                const timeCell = row.cells[5];
                if (timeCell) {
                    timeCell.innerText = new Date().toLocaleTimeString();
                }
            }
        }
    });

    // If not found, it's a new device!
    // We should trigger a refresh or add row.
    // To avoid flashing, let's just refresh for now if not found (throttled)
    if (!found) {
        if (!isFetching) refreshDevices();
    }
});

// Handle Device Offline Event
socket.on('device_offline', (data) => {
    const rows = document.querySelectorAll('#devicesList tr');
    rows.forEach(row => {
        const ipCell = row.cells[0];
        if (ipCell && ipCell.innerText.trim() === data.ip) {
            // Apply Offline Styles
            row.classList.add('offline-row');
            row.style.opacity = '0.5';
            row.style.filter = 'grayscale(100%)';
            row.style.borderLeft = '3px solid var(--danger)';
            row.style.background = 'rgba(239, 68, 68, 0.05)';

            // Update Status Badge
            const statusCell = row.cells[4];
            if (statusCell) {
                statusCell.innerHTML = '<span class="badge danger">Offline</span>';
            }
        }
    });
});

