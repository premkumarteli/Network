# Lite Network Sensor - Setup Guide

This is a lightweight network sensor designed to capture DNS traffic and report it back to a central Netvisor server.

## 1. Requirements
- Python 3.x
- Npcap (on Windows) or libpcap (on Linux)
- Python libraries: `scapy`, `requests`

## 2. Installation
Open your terminal and run:
pip install scapy requests

## 3. Configuration
Open `core/config.json` and ensure:
- `server_url`: https://netvisor-prem-2026.loca.lt/api/v1/collect/packet
- `api_key`: Matches the server's agent key.
- `agent_id`: A unique name for this device.

## 4. Running the Sensor
Run the following command (Administrator/Root privileges required for packet capture):
python sensor.py
