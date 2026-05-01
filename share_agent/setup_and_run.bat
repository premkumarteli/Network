@echo off
echo =========================================
echo NetVisor Agent Setup (Windows)
echo =========================================

echo 1. Installing Python dependencies...
pip install -r requirements-agent.txt
if %errorlevel% neq 0 (
    echo [!] Failed to install dependencies. Please ensure Python and pip are installed.
    pause
    exit /b %errorlevel%
)

echo.
set /p SERVER_IP="Enter the MAIN SERVER IP Address (e.g., 192.168.1.100): "

echo 2. Updating configuration...
python -c "import json; config_file='config/agent.json'; data=json.load(open(config_file)); data['server_url']=f'http://{SERVER_IP}:8000/api/v1/collect/packet'; data['heartbeat_url']=f'http://{SERVER_IP}:8000/api/v1/collect/heartbeat'; json.dump(data, open(config_file, 'w'), indent=2)"

echo 3. Starting the NetVisor Agent...
echo Please ensure you ran this script as Administrator so the packet capture works!
python run_agent.py
pause
