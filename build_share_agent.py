import os
import shutil
import zipfile

def main():
    base_dir = r"c:\Users\prem\Network"
    output_dir = os.path.join(base_dir, "share_agent")
    
    # Clean up previous directory if it exists
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir)

    print("Copying necessary files...")
    # Directories to copy
    dirs_to_copy = ["agent", "shared", "config"]
    for d in dirs_to_copy:
        src = os.path.join(base_dir, d)
        dst = os.path.join(output_dir, d)
        if os.path.exists(src):
            # Ignore __pycache__
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns('__pycache__'))

    # Files to copy
    files_to_copy = ["run_agent.py", "requirements-agent.txt", ".env"]
    for f in files_to_copy:
        src = os.path.join(base_dir, f)
        dst = os.path.join(output_dir, f)
        if os.path.exists(src):
            shutil.copy2(src, dst)

    print("Generating Windows setup script...")
    bat_content = """@echo off
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
python -c "import json, os; config_file='config/agent.json'; data=json.load(open(config_file)); ip=os.environ.get('SERVER_IP'); data['server_url']='http://'+ip+':8000/api/v1/collect/packet'; data['heartbeat_url']='http://'+ip+':8000/api/v1/collect/heartbeat'; json.dump(data, open(config_file, 'w'), indent=2)"

echo 3. Starting the NetVisor Agent...
echo Please ensure you ran this script as Administrator so the packet capture works!
python run_agent.py
pause
"""
    with open(os.path.join(output_dir, "setup_and_run.bat"), "w") as f:
        f.write(bat_content)

    print("Generating Linux/macOS setup script...")
    sh_content = """#!/bin/bash
echo "========================================="
echo "NetVisor Agent Setup (Linux/macOS)"
echo "========================================="

echo "1. Installing Python dependencies..."
pip install -r requirements-agent.txt || pip3 install -r requirements-agent.txt

echo ""
read -p "Enter the MAIN SERVER IP Address (e.g., 192.168.1.100): " SERVER_IP

echo "2. Updating configuration..."
python3 -c "import json; config_file='config/agent.json'; data=json.load(open(config_file)); data['server_url']=f'http://${SERVER_IP}:8000/api/v1/collect/packet'; data['heartbeat_url']=f'http://${SERVER_IP}:8000/api/v1/collect/heartbeat'; json.dump(data, open(config_file, 'w'), indent=2)" || python -c "import json; config_file='config/agent.json'; data=json.load(open(config_file)); data['server_url']=f'http://${SERVER_IP}:8000/api/v1/collect/packet'; data['heartbeat_url']=f'http://${SERVER_IP}:8000/api/v1/collect/heartbeat'; json.dump(data, open(config_file, 'w'), indent=2)"

echo "3. Starting the NetVisor Agent..."
echo "Running as sudo for packet capture permissions..."
sudo python3 run_agent.py || sudo python run_agent.py
"""
    with open(os.path.join(output_dir, "setup_and_run.sh"), "w", newline='\n') as f:
        f.write(sh_content)

    print("Zipping the shareable package...")
    zip_path = os.path.join(base_dir, "share_agent.zip")
    if os.path.exists(zip_path):
        os.remove(zip_path)
        
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, base_dir)
                zipf.write(file_path, arcname)

    print(f"\\nSUCCESS! Created {zip_path}")
    print("You can copy 'share_agent.zip' to your other system, extract it, and run the setup script.")

if __name__ == "__main__":
    main()
