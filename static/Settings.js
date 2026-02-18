// settings.js
const iface = document.getElementById("iface");
const startBtn = document.getElementById("startBtn");
const stopBtn = document.getElementById("stopBtn");
const statusEl = document.getElementById("status");

startBtn.addEventListener("click", async () => {
  try {
    const res = await fetch('/api/start-monitor', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ iface: iface.value }) });
    const data = await res.json();
    statusEl.innerText = data.message || "Started";
  } catch(e){
    statusEl.innerText = "Error starting monitor";
  }
});

stopBtn.addEventListener("click", async () => {
  try {
    const res = await fetch('/api/stop-monitor', { method: 'POST' });
    const data = await res.json();
    statusEl.innerText = data.message || "Stopped";
  } catch(e){
    statusEl.innerText = "Error stopping monitor";
  }
});
async function loadStatus(){
  try {
    const res = await fetch('/api/monitor-status');
    const data = await res.json();
    statusEl.innerText = data.status || "Unknown";
    iface.value = data.iface || "";
  } catch(e){
    statusEl.innerText = "Error loading status";
  }
}
loadStatus();
setInterval(loadStatus, 5000);
  