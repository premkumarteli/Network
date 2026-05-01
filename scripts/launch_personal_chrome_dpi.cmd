@echo off
set NETVISOR_PROXY=http://127.0.0.1:8899
echo [*] Starting Personal Chrome with NetVisor DPI Proxy...
echo [!] Note: Close all other Chrome instances first for this to apply to your default profile.
start "Chrome DPI" "C:\Program Files\Google\Chrome\Application\chrome.exe" --proxy-server=%NETVISOR_PROXY% %*
