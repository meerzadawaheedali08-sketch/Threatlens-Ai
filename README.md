# 🛡️ ThreatLens AI

**ThreatLens AI** is an interactive, educational cybersecurity platform designed to simplify threat analysis for students, developers, and security enthusiasts. By pairing live threat intelligence with generative AI, it translates complex security metrics into clear, actionable insights for all expertise levels.

---

### ✨ Key Features & Capabilities

* **Multi-Target Analysis:** Scans domains, URLs, IPv4, and IPv6 addresses within a unified interface.
* **Deterministic Risk Scoring:** Combines multi-vendor malicious detection counts from **VirusTotal** with domain ownership metrics from **WHOIS** to calculate a precise 0–100 risk score.
* **Adaptive Gemini AI Layer:** Utilizes Google Gemini (`gemini-2.5-flash`) to generate contextual security summaries tailored to **Beginner**, **Intermediate**, or **Expert** explanation modes.
* **Resilient Infrastructure:** Implements custom exception handlers to provide continuous service and technical feedback even during upstream API rate limits.
* **Exportable Audit Reports:** Generates structured **JSON** and formatted **TXT** security reports for offline review and documentation.

---

### 🛠️ Technology Stack

* **Frontend & Framework:** Streamlit, Custom CSS
* **Language & Core Logic:** Python 3.10+
* **Intelligence Providers:** VirusTotal API v3, WHOIS Protocol
* **Generative AI Engine:** Google GenAI SDK (`gemini-2.5-flash`)
* **Deployment & Tunneling:** Google Colab, Cloudflare Tunnel (`cloudflared`)

---

### 🎓 Educational Purpose & Disclaimer

ThreatLens AI is an open-access educational tool designed to help users understand cybersecurity indicators of compromise (IOCs). While the platform aggregates real-time metrics from global security databases, zero malicious detections do not guarantee absolute safety. Always practice defense-in-depth and safe browsing habits online!

***

**Designed & Developed by:** Waheed Ali Hamouzai
