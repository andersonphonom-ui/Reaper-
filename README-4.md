# 💀 Reaper

**Reaper** is a Python-based web vulnerability scanner that automatically detects security flaws in websites — SQL Injection, XSS, missing security headers, exposed admin panels, and sensitive files — all from your terminal.

> ⚠️ **Disclaimer:** This tool is for educational purposes only. Only scan websites you own or have explicit permission to test.

---

## ✨ Features

| Module | What it detects |
|---|---|
| 💉 SQL Injection | Detects SQLi via error-based detection |
| 🔥 XSS | Detects Reflected XSS via payload injection |
| 🛡️ Security Headers | Detects missing HTTP security headers |
| 🚪 Admin Panels | Finds exposed admin/login pages |
| 📁 Sensitive Files | Finds exposed .env, .git, backups, configs |

---

## 📦 Installation

```bash
git clone https://github.com/andersonphonom-ui/reaper.git
cd reaper
pip install -r requirements.txt --break-system-packages
sudo cp main.py scanner.py banner.py /usr/local/bin/
sudo cp -r modules/ /usr/local/bin/modules/
sudo mv /usr/local/bin/main.py /usr/local/bin/reaper
sudo chmod +x /usr/local/bin/reaper
```

---

## 🚀 Usage

```bash
# Full scan — all modules
reaper -u https://example.com

# Specific module
reaper -u https://example.com -m sqli
reaper -u https://example.com -m xss
reaper -u https://example.com -m headers
reaper -u https://example.com -m admin
reaper -u https://example.com -m files

# Multiple modules
reaper -u https://example.com -m sqli xss headers

# Custom timeout
reaper -u https://example.com -t 10

# Help
reaper -h

# Version
reaper -v
```

---

## 📊 Example Output

```
💀 Reaper Report — https://example.com
╔══╤══════════════════════════════╤═══════════════╤══════════════════╤═══════════════════════════════════╗
║ #│ Type                         │ Severity      │ Parameter/Path   │ Evidence                          ║
╟──┼──────────────────────────────┼───────────────┼──────────────────┼───────────────────────────────────╢
║ 1│ SQL Injection                │ Critical 🔴   │ id               │ sql syntax                        ║
║ 2│ Reflected XSS                │ Critical 🔴   │ search           │ Payload reflected in response     ║
║ 3│ Admin Panel Found            │ High 🟠       │ /admin           │ Status: 200                       ║
║ 4│ Missing Header: CSP          │ High 🟠       │ -                │ Protects against XSS              ║
║ 5│ Sensitive File Exposed       │ Critical 🔴   │ /.env            │ Environment file exposed          ║
╚══╧══════════════════════════════╧═══════════════╧══════════════════╧═══════════════════════════════════╝

Risk Score : 85/100
Risk Level : Critical 🔴
```

---

## 🗂️ Project Structure

```
reaper/
├── main.py          # CLI entry point
├── scanner.py       # Scan orchestrator + report
├── banner.py        # ASCII art banner
├── requirements.txt
└── modules/
    ├── sqli.py      # SQL Injection module
    ├── xss.py       # XSS module
    ├── headers.py   # Security headers module
    ├── admin.py     # Admin panel finder
    └── files.py     # Sensitive files finder
```

---

## ⚙️ Available Modules

| Module | Flag |
|---|---|
| SQL Injection | `-m sqli` |
| XSS | `-m xss` |
| Security Headers | `-m headers` |
| Admin Panels | `-m admin` |
| Sensitive Files | `-m files` |

---

## 👨‍💻 Author

**Youssef Mediouni**
- YouTube: [PH4nt0m CYber](https://youtube.com/@PH4nt0mCYber)
- GitHub: [@andersonphonom-ui](https://github.com/andersonphonom-ui)

---

## 📄 License

MIT License — free to use, modify, and distribute.
