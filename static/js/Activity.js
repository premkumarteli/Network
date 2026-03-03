async function refreshActivity() {
  try {
    const res = await fetch("/api/activity");
    const logs = await res.json();

    const tbody = document.getElementById("activity-table-body");
    if (tbody) {
      if (logs.length === 0) {
        tbody.innerHTML =
          '<tr><td colspan="6" style="text-align:center; color: var(--text-muted);">No activity logs</td></tr>';
      } else {
        tbody.innerHTML = logs
          .map(
            (l) => `
                    <tr>
                        <td class="mono" style="color: var(--text-muted);">${l.time}</td>
                        <td class="mono">
                            <div style="color: var(--primary);">${l.ip}</div>
                            <div style="font-size: 0.75rem; color: var(--text-muted); opacity: 0.8;">
                                ${l.device !== "Unknown" ? `<span>${l.device}</span> • ` : ""}
                                <span>${l.os}</span> • <span>${l.brand}</span>
                            </div>
                        </td>
                        <td class="mono">${l.dst_ip || "-"}</td>
                        <td>${l.domain || "-"}</td>
                        <td><span class="badge">${l.protocol}</span></td>
                        <td class="mono">${l.size}</td>
                    </tr>
                `,
          )
          .join("");
      }
    }
  } catch (e) {
    console.error("Error fetching activity:", e);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshActivity();
  setInterval(refreshActivity, 3000);
});
