# Rust Distributed Web Vulnerability Scanner

A **high-performance distributed web vulnerability scanner built with Rust**.  
This project detects common web vulnerabilities across large targets by distributing scanning workloads across multiple worker nodes.

The scanner architecture is inspired by tools such as **OWASP ZAP**, **Nikto**, and **Burp Suite**, but focuses on **performance, scalability, and modularity using Rust**.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [System Components](#system-components)
- [Project Structure](#project-structure)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Running the System](#running-the-system)
- [Example Scan Workflow](#example-scan-workflow)
- [Vulnerability Detection Modules](#vulnerability-detection-modules)
- [Future Improvements](#future-improvements)
- [Security Notice](#security-notice)
- [License](#license)

---

## Overview

Traditional vulnerability scanners run on a single machine, which limits scanning speed and scalability.

This project introduces a **distributed architecture** where:

- A **Coordinator Server** manages scans and distributes tasks
- Multiple **Worker Nodes** perform scanning in parallel
- Results are collected and visualized via a **Dashboard**

The system is designed for:

- High-performance scanning
- Large-scale targets
- Extensible vulnerability detection modules
- Distributed security testing environments

---

## Architecture

```
            ┌──────────────────────┐
            │       Web UI         │
            │   Dashboard / API    │
            └─────────┬────────────┘
                      │
                    REST
                      │
            ┌─────────▼───────────┐
            │     Coordinator      │
            │  Scan Controller     │
            │  Task Scheduler      │
            └───────┬───────┬─────┘
                    │       │
                Task Queue  Database
                    │
     ┌──────────────┴──────────────┐
     │                             │
┌────▼────────┐               ┌────▼────────┐
│ Worker Node │               │ Worker Node │
│  Crawler    │               │  Scanner    │
│  Vulnerability Engine       │             │
└──────┬──────┘               └──────┬──────┘
       │                             │
       └────── Scan Target Websites ─┘
```

---

## Features

### Distributed Scanning
Multiple worker nodes scan targets concurrently.

### Intelligent Web Crawling
Automatically discovers endpoints and parameters.

### Modular Vulnerability Detection
Each vulnerability type is implemented as a plugin module.

### Real-Time Scan Monitoring
Dashboard displays scan progress and discovered vulnerabilities.

### Parallel Scanning
Uses Rust async runtime to efficiently process large workloads.

### Extensible Plugin System
New vulnerability modules can be added easily.

---

## System Components

### Coordinator Server

The **central control system**.

Responsibilities:

- Manage scan jobs
- Distribute tasks to workers
- Collect results
- Maintain scan state
- Monitor worker health

**API Endpoints:**

```
POST /scan/start
GET  /scan/{scan_id}
GET  /scan/{scan_id}/results
GET  /workers/status
```

Example request:

```json
{
  "target": "https://example.com",
  "depth": 3,
  "modules": ["xss", "sqli", "dir_enum"]
}
```

---

### Worker Nodes

Workers perform the **actual vulnerability scanning**.

Responsibilities:

1. Receive scan tasks
2. Crawl target URLs
3. Run vulnerability tests
4. Send results back to coordinator

Workers are **stateless**, allowing horizontal scaling.

---

### Crawler Engine

The crawler discovers endpoints and URLs for scanning.

**Crawling Process:**

1. Fetch webpage
2. Parse HTML
3. Extract links
4. Normalize URLs
5. Remove duplicates
6. Respect crawl depth

Example discovered endpoints:

```
https://example.com/login
https://example.com/products
https://example.com/products?id=10
https://example.com/admin
```

---

## Vulnerability Detection Modules

Each vulnerability is implemented as an independent module. Modules can be enabled or disabled during scan configuration.

### Cross-Site Scripting (XSS)

Inject payloads into parameters and detect reflection.

Example payload:

```
"><script>alert(1)</script>
```

### SQL Injection

Test for database query manipulation.

Example payloads:

```
' OR 1=1--
' OR '1'='1
```

Detection methods: SQL error responses, response differences, time delays.

---

### Directory Enumeration

Discover hidden directories using wordlists similar to directory brute-force tools.

Example targets:

```
/admin
/backup
/config
/.git
/dashboard
```

---

### Security Header Analysis

Checks for missing security headers such as:

```
Content-Security-Policy
X-Frame-Options
Strict-Transport-Security
X-Content-Type-Options
```

---

## Task Queue

The coordinator distributes scanning tasks through a message queue.

Example task structure:

```json
{
  "scan_id": 12,
  "url": "https://example.com/products",
  "module": "xss"
}
```

Workers continuously fetch tasks from the queue.

---

## Result Storage

All scan results are stored in a database.

**`scans` table:**

| Column | Type |
|---|---|
| id | integer |
| target | text |
| status | text |
| started_at | timestamp |
| completed_at | timestamp |

**`findings` table:**

| Column | Type |
|---|---|
| id | integer |
| scan_id | integer |
| url | text |
| vulnerability | text |
| severity | text |
| payload | text |
| evidence | text |

---

## Web Dashboard

The dashboard provides real-time visualization.

Features:

- Scan progress
- Vulnerability reports
- Severity categorization
- Historical scans

Example report:

```
Target: example.com
Scan progress: 73%

Findings:

HIGH   — SQL Injection      /login
MEDIUM — XSS                /search?q=
LOW    — Missing Sec Headers
```

---

## Project Structure

```
rust-distributed-scanner/
├── coordinator/
│   └── src/
│       ├── api/
│       └── scheduler/
├── worker/
│   └── src/
│       ├── crawler/
│       └── scanner/
├── modules/
│   ├── xss.rs
│   ├── sqli.rs
│   ├── dir_enum.rs
│   └── headers.rs
├── common/
│   ├── models/
│   └── messaging/
└── dashboard/
    └── frontend/
```

---

## Technology Stack

### Core Rust

| Crate | Purpose |
|---|---|
| `tokio` | Async runtime |
| `reqwest` | HTTP client |
| `axum` | Web framework |
| `serde` | Serialization |
| `scraper` | HTML parsing |
| `sqlx` | Database access |
| `rayon` | Parallel computation |

### Infrastructure

| Tool | Role |
|---|---|
| PostgreSQL | Result storage |
| Redis / NATS | Task queue |
| Docker | Containerization |
| Kubernetes | Orchestration (optional) |

---

## Installation

### Requirements

- Rust + Cargo
- PostgreSQL
- Redis (or NATS)
- Docker (optional)

**Install Rust:**

```bash
curl https://sh.rustup.rs -sSf | sh
```

**Clone the repository:**

```bash
git clone https://github.com/username/rust-distributed-scanner.git
cd rust-distributed-scanner
```

---

## Running the System

**Start the database:**

```bash
docker run -p 5432:5432 postgres
```

**Start the coordinator:**

```bash
cd coordinator
cargo run
```

**Start a worker node:**

```bash
cd worker
cargo run
```

You can run multiple workers in parallel:

```bash
cargo run &
cargo run &
cargo run &
```

---

## Example Scan Workflow

1. User submits target via API or dashboard
2. Coordinator creates scan job
3. URLs are added to task queue
4. Workers retrieve tasks
5. Crawlers discover endpoints
6. Vulnerability modules run tests
7. Results sent back to coordinator
8. Dashboard updates findings

---

## Future Improvements

- Distributed crawling synchronization
- Rate limiting to prevent target overload
- Screenshot capture of vulnerable pages
- Machine learning anomaly detection
- GraphQL vulnerability module
- JWT security module
- Subdomain enumeration
- Automatic PDF report generation

---

## Security Notice

> ⚠️ This tool is intended **for educational and authorized security testing purposes only**.

Only scan systems you own or have **explicit written permission** to test. Unauthorized scanning may be illegal.

---

## License

MIT License
