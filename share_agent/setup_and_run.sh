#!/bin/bash
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
