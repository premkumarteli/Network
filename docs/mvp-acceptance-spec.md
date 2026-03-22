# NetVisor MVP Acceptance Spec

## Purpose

This document defines the minimum detection scenarios that must work before NetVisor MVP is considered ready.

## Acceptance Rules

- alerts must be generated within 5 seconds of detection input
- alerts must contain alert type, severity, timestamp, and affected device or flow
- risk scoring must be visible in the admin dashboard
- no payload may be stored for BYOD traffic

## Scenario 1: Port Scan Detection

### Input

A single source attempts connections to multiple destination ports within a short time window.

### Detection Logic

- source IP touches `X` distinct ports within `Y` seconds
- exact thresholds are implementation-configurable, but the behavior must be deterministic and testable

### Expected Alert

- title: `Port Scanning Detected`
- severity: `HIGH`
- output includes source IP, target IP or range, port count, and timestamp

## Scenario 2: Suspicious Outbound Beaconing

### Input

A device creates repeated outbound connections to the same destination at nearly fixed intervals.

### Detection Logic

- repeated connections to the same IP or domain
- low variance in inter-arrival timing

### Expected Alert

- title: `Possible C2 Beaconing`
- severity: `HIGH`
- output includes source, destination, interval summary, and timestamp

## Scenario 3: Traffic Spike or Behavioral Anomaly

### Input

A device shows an unusual increase in traffic volume or flow behavior relative to its recent baseline.

### Detection Logic

- Isolation Forest anomaly score exceeds configured threshold
- or baseline deviation logic marks the flow or time window as abnormal

### Expected Alert

- title: `Anomalous Traffic Behavior`
- severity: `MEDIUM` to `HIGH`
- output includes anomaly score, device, and timestamp

## Scenario 4: Blacklisted IP Communication

### Input

A device communicates with a known malicious IP address.

### Detection Logic

- destination IP matches configured static blacklist

### Expected Alert

- title: `Malicious IP Communication`
- severity: `CRITICAL`
- output includes source IP, malicious IP, and timestamp

## Scenario 5: VPN or Proxy Suspicion

### Input

A device creates a long-lived encrypted connection with uniform packet size and suspicious destination characteristics.

### Detection Logic

- flow pattern indicates probable VPN or proxy usage
- ASN or static destination matching may contribute to detection

### Expected Alert

- title: `Possible VPN/Proxy Usage`
- severity: `MEDIUM`
- output includes source IP, destination, supporting indicators, and timestamp

## MVP System Acceptance

NetVisor MVP is accepted only when all of the following are true:

- agent and gateway both submit flow data successfully
- at least one simulated attack can be reproduced end to end
- backend generates correct alert severity for each required scenario
- admin dashboard displays new alerts and updated risk data in near real time
- user dashboard shows safety score and transparency log
- BYOD traffic handling remains metadata-only
