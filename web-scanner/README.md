# WebScan Backend (Rust)

A high-performance coordinator and scanner written in **Rust** for web vulnerability scanning.

## ⚙️ Core Architecture

- **Coordinator API**: Uses `axum` for HTTP endpoints.
- **Worker Engine**: Spawns asynchronous tasks with `tokio::spawn` to run scans without blocking the API.
- **Intelligent Crawler**: Uses `reqwest` and `scraper` to discover local URLs.
- **Vulnerability Checks**:
  - `MissingHeader`: Checks for `strict-transport-security`, `content-security-policy`, `x-frame-options`, `x-content-type-options`.
  - `DirectoryEnumeration`: Checks for sensitive paths (`/admin`, `.git`, `.env`).
  - `ConnectionError`: Reports unreachable targets as "HIGH" severity.

## 🚀 Get Started

1. Go to the backend folder:
```bash
cd web-scanner
```
2. Build and run:
```bash
cargo run
```
Starts listening on `http://localhost:3000`.

## 📡 API Reference

- `POST /scan/start`: Begins a new scan job.
- `GET /scan/:id`: Retrieves scan results and findings.

## 🛡️ License
MIT
