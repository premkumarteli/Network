# NetVisor MVP Architecture Spec

## Product Context

NetVisor MVP is a single-organization, self-hosted threat detection and SOC-style monitoring product for mixed environments with managed devices and BYOD devices.

## Architecture Components

- `frontend`: React admin and user dashboards
- `backend`: FastAPI API, auth, risk scoring, alerting, storage
- `agent`: endpoint process on managed devices
- `gateway`: software packet capture and flow aggregation service for network traffic
- `database`: local persistence for flows, alerts, users, audit logs, and device state

## Gateway Design

The MVP gateway is a software-based packet capture service using Scapy.

It runs in one of two modes:

- single NIC with promiscuous mode enabled
- mirror or SPAN port capture, preferred when available

The gateway is not a NetFlow collector for MVP.

## Gateway Data Path

The gateway processes traffic as:

`packet -> metadata extraction -> flow aggregation -> backend submission`

The gateway must never persist or forward payload content.

## Managed vs BYOD Classification

Managed device classification is final for MVP:

- managed device = agent installed and successfully registered with backend
- BYOD device = any device observed by gateway without an active registered agent

Future extensions such as MAC allowlists or enrollment tokens are explicitly out of scope for MVP.

## Payload Access Rules

### Agent

- allowed payload access for managed devices only
- payload access is limited to simulated DPI logic
- payload may exist in memory only
- payload must never be written to disk or sent to backend

### Gateway

- must never inspect or store BYOD payload
- may extract metadata only

### Backend

- must never store payload from any source
- stores flow metadata, derived indicators, alerts, audit logs, and device state only

## Allowed BYOD Metadata

The gateway may extract only:

- source IP
- destination IP
- destination port
- protocol
- packet size
- timestamp
- flow duration
- packet count
- DNS domain, if available from query metadata

The gateway must not store:

- payload
- full HTTP content
- decrypted TLS data

## Real-Time Requirement

NetVisor MVP defines real-time as alert visibility within 5 seconds of observation.

Operational target:

- flow aggregation window: 3 to 5 seconds
- alert generation deadline: 5 seconds end to end

## Retention Policy

Default MVP retention:

- flows: 24 to 48 hours
- alerts: 7 days
- audit logs: 7 days

Retention should be configurable, but these defaults define MVP behavior.

## MVP Architecture Consequences

The codebase must reflect these decisions:

- no multi-tenant behavior in MVP runtime
- gateway must be a clear module or service, separate from managed-device agent logic
- BYOD privacy boundary must be enforced in code, not only in documentation
- payload-derived data must stay local to managed-device agents
