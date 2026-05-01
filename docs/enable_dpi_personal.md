# Enabling DPI on Your Personal Browser

To analyze traffic from your personal Chrome or Edge instance, follow these steps:

## 1. Verify the Certificate
The NetVisor CA certificate allows the agent to inspect HTTPS traffic. I have verified that it is already installed on your system. If you see "Not Private" warnings, you may need to manually re-install it from:
`C:\Users\prem\Network\runtime\agent\mitm\netvisor-agent-root.pem`

## 2. Configure the Proxy
The NetVisor agent listens for web traffic on `127.0.0.1:8899`. You can use a browser extension like **Proxy SwitchyOmega** to route your traffic there.

### Extension Settings:
- **Protocol**: HTTP
- **Server**: `127.0.0.1`
- **Port**: `8899`

## 3. Simplified Launch Script
Alternatively, you can use the provided script to launch your personal Chrome with the proxy enabled:
`C:\Users\prem\Network\scripts\launch_personal_chrome_dpi.cmd`

> [!WARNING]
> For the launch script to work on your default profile, you must **close all existing Chrome windows** first.
