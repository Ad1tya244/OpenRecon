# OpenRecon

**OpenRecon** is a powerful, passive OSINT (Open Source Intelligence) reconnaissance tool and Attack Surface Management (ASM) dashboard. It allows security researchers and administrators to gain visibility into the external attack surface of a target domain without sending aggressive payloads.

![OpenRecon Dashboard](https://via.placeholder.com/800x400?text=OpenRecon+Dashboard+Preview)

## 🚀 Features

OpenRecon aggregates intelligence from multiple sources to build a comprehensive profile:

*   **🛡️ Passive Subdomain Enumeration**: Discover subdomains without brute-forcing, using certificate transparency logs and public sources.
*   **🌐 DNS & Whois Intelligence**: detailed DNS records (A, MX, TXT, SPF, DMARC) and domain registration details.
*   **🔒 SSL/TLS Analysis**: Certificate validity, issuer, age, and security grades.
*   **🧱 Technology Fingerprinting**: Detect server types, CMS (WordPress, Drupal), proxies, and frameworks via reaction-based analysis.
*   **🔌 Open Port Scanning**: Top 10 common port checks (HTTP, HTTPS, SSH, FTP, etc.) done safely.
*   **🔐 Security Headers**: Analyze missing or misconfigured security headers (HSTS, CSP, X-Frame-Options).
*   **🕸️ Network Footprint**: Map unique IP addresses, ASNs, and hosting providers associated with the domain infrastructure.
*   **📜 Code Leak Intelligence**: Check for potential secrets or repository leaks on platforms like GitHub.
*   **📂 Public Files**: exposure check for sensitive files like `robots.txt`, `sitemap.xml`, `.enz`, etc.
*   **⏳ Historical Intel**: specific analysis of past endpoints and tech stacks using Wayback Machine data.
*   **📊 Attack Surface Graph**: Interactive visualization correlating Domains -> Subdomains -> IPs -> Risks.
*   **📄 PDF Reporting**: Generate professional-grade reconnaissance reports with one click.

## 🛠️ Technology Stack

### Backend
*   **Language**: Python 3.12+
*   **Framework**: [FastAPI](https://fastapi.tiangolo.com/) (High-performance Async API)
*   **Server**: Uvicorn
*   **Libraries**: `dnspython`, `python-whois`, `httpx`, `beautifulsoup4`

### Frontend
*   **Framework**: [React](https://react.dev/) (v18)
*   **Build Tool**: [Vite](https://vitejs.dev/)
*   **Styling**: Plain CSS / CSS Modules (Modern Dark Mode Design)
*   **Visualization**: Custom D3-like SVG rendering for Graphs

## 💻 System Requirements

*   **OS**: macOS, Linux, or Windows (WSL recommended)
*   **Software**:
    *   **Node.js**: v18 or higher
    *   **npm**: v9 or higher
    *   **Python**: v3.12 or higher
    *   **pip**: Latest version

## 📥 Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/your-repo/openrecon.git
    cd openrecon
    ```

2.  **Install Backend Dependencies**
    ```bash
    cd backend
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    pip install -r requirements.txt
    cd ..
    ```

3.  **Install Frontend Dependencies**
    ```bash
    cd frontend
    npm install
    cd ..
    ```

4.  **Install Root Dev Tools** (Optional, for concurrent running)
    ```bash
    npm install
    ```

## ⚡ Usage

### Running the Application (Recommended)
OpenRecon uses a unified script to start both Backend and Frontend simultaneously.

From the **root directory**:
```bash
npm run dev
```
*   **Frontend**: Available at `http://localhost:5173`
*   **Backend API**: Available at `http://localhost:8000`
*   **API Docs**: `http://localhost:8000/docs` (if enabled)

### Terminating the Program
To stop the servers, simply press:
**`Ctrl + C`** in the terminal where the program is running.

## 🛑 Disclaimer
**OpenRecon is intended for educational and defensive purposes only.**
By using this tool, you agree to:
1.  Only scan domains you own or have explicit permission to audit.
2.  Not use this tool for malicious purposes or unauthorized entry.
3.  The developers are not liable for any misuse or legal consequences resulting from the use of this tool.

---
*Created by the OpenRecon Team*
