# NetVisor MVP UI and RBAC Spec

## Roles

NetVisor MVP has two roles only:

- `admin`
- `user`

## Admin Dashboard

The admin dashboard is the primary operational interface.

### Overview Page

Required widgets:

- total devices
- active flows
- alert count
- risk distribution chart

### Alerts Panel

Required capabilities:

- alert list with time, type, severity, device, and status
- filtering by severity
- filtering by device

### Device View

Required fields:

- device name or identifier
- managed vs BYOD classification
- device status
- current risk score

### Flow Monitor

Required elements:

- top talkers
- live traffic table
- recent suspicious flows

## User Dashboard

The user dashboard is limited and transparency-focused.

Required fields:

- safety score from 0 to 100
- recent activity summary
- alerts affecting the user's device
- transparency log

## Transparency Log Rules

The transparency log may show only:

- source IP
- destination IP
- domain, if available
- timestamp

The transparency log must not show:

- payload
- HTTP content
- decrypted application content
- unrelated organization-wide data

## RBAC Matrix

### Admin Permissions

- view all devices
- view all alerts
- view all relevant flows
- view risk scores across the environment
- trigger simulated isolation actions

### User Permissions

- view own device-related data only
- view limited alerts affecting own device
- view own transparency log

## RBAC Table

| Action | Admin | User |
| --- | --- | --- |
| View all devices | Yes | No |
| View own data | Yes | Yes |
| View alerts | Yes | Limited |
| Trigger isolation (simulated) | Yes | No |
| View transparency log | No | Yes |

## UI MVP Consequences

The frontend must be updated so that:

- admin pages use real backend data instead of placeholders
- user pages reflect transparency-first privacy boundaries
- risk scoring is visible in admin views
- managed vs BYOD status is visible in device views
