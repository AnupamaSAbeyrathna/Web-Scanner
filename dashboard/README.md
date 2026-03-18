# WebScan · Vulnerability Dashboard

A high-performance React (Vite) frontend for the **WebScan** vulnerability scanner.

## ✨ Features
- **Real-time Status Polling**: Fetches scan job updates every 1.5 seconds.
- **Dynamic Findings List**: Lists findings with icons for each type.
- **Severity Ranking**: Automatically sorts findings by HIGH > MEDIUM > LOW.
- **Scan History**: Keeps track of all scan jobs submitted in the session.
- **Deep Polling Logic**: Intelligent `setInterval` ensures only active scans poll the API.
- **Premium Dark UI**: Built with custom Inter & JetBrains Mono typography.

## 🚀 Get Started
1. Ensure the Rust backend is running on `localhost:3000`.
2. Run the frontend:
```bash
npm install
npm run dev
```
3. Open `http://localhost:5173`.

## 🛠️ Stack
- **Framework**: React 18+
- **Tooling**: Vite 5+
- **Styling**: Vanilla CSS (CSS Variables)
- **API Communication**: `fetch` API

## 🛡️ License
MIT
