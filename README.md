# WebScan: Distributed Web Vulnerability Scanner

A high-performance, distributed web vulnerability scanner built with **Rust** and **React**.

## 🚀 Key Features

- **Distributed Architecture**: Coordinator handles API requests and spawns scan tasks asynchronously.
- **Intelligent Crawler**: Automatically discovers local links within the target domain.
- **Plugin-based Vulnerability Engine**:
  - **🛡️ Security Headers Analysis**: Detects missing critical security headers (CSP, HSTS, etc.).
  - **📂 Directory Discovery**: Brute-forces sensitive paths like `/.git/`, `/admin`, and `/.env`.
  - **🔌 Intelligent Error Handling**: Detects and reports connection failures with "HIGH" severity.
- **Live Dashboard**: React-based UI with real-time polling to visualize scan progress and findings.
- **Premium Design**: Sleek dark-mode interface with color-coded severity levels.

---

## 🏗️ Project Structure

```text
Port Scanner/
├── web-scanner/     # Rust (Axum) Backend Coordinator & Worker
│   ├── src/
│   │   ├── main.rs     # API Server & Router
│   │   ├── scanner.rs  # Crawler & Vulnerability Engine
│   │   └── model.rs    # Shared Data Structures
│   └── Cargo.toml      # Backend Dependencies
├── dashboard/       # React (Vite) Frontend
│   ├── src/
│   │   ├── App.jsx     # Frontend Logic & UI
│   │   └── App.css     # Premium Styling
│   └── index.html      # Main Entry Point
└── notes/           # Design & Architecture Specification
```

---

## 🛠️ Quick Start

### 1. Prerequisites
- **Rust** (Cargo)
- **Node.js** (npm)

### 2. Run the Backend (Rust)
```bash
cd web-scanner
cargo run
```
The coordinator will start listening on `http://localhost:3000`.

### 3. Run the Frontend (React)
```bash
cd dashboard
npm install
npm run dev
```
The dashboard will be available at `http://localhost:5173`.

---

## 📡 API Reference

### Start a Scan
`POST /scan/start`
```json
{
  "target": "https://example.com"
}
```

### Get Scan Results
`GET /scan/:id`

---

## 🔒 Security Notice

⚠️ **This tool is for educational and authorized security testing ONLY.**  
Do not scan websites you do not own or have explicit permission to test and scan.

---

## 📜 License
MIT
