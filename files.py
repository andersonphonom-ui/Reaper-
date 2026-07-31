import requests

SENSITIVE_FILES = [
    ("/.env",                  "Critical 🔴", "Environment file — may contain API keys and passwords"),
    ("/.git/config",           "Critical 🔴", "Git config — source code may be exposed"),
    ("/.git/HEAD",             "Critical 🔴", "Git repository exposed"),
    ("/backup.zip",            "Critical 🔴", "Backup archive exposed"),
    ("/backup.sql",            "Critical 🔴", "Database backup exposed"),
    ("/db.sql",                "Critical 🔴", "Database file exposed"),
    ("/config.php",            "High 🟠",     "PHP config file"),
    ("/config.yml",            "High 🟠",     "YAML config file"),
    ("/config.json",           "High 🟠",     "JSON config file"),
    ("/.htpasswd",             "High 🟠",     "Password file exposed"),
    ("/.htaccess",             "Medium 🟡",   "Apache config file"),
    ("/robots.txt",            "Low 🔵",      "May reveal hidden paths"),
    ("/sitemap.xml",           "Low 🔵",      "Site structure exposed"),
    ("/phpinfo.php",           "High 🟠",     "PHP info page — reveals server details"),
    ("/info.php",              "High 🟠",     "PHP info page"),
    ("/test.php",              "Medium 🟡",   "Test file left on server"),
    ("/wp-config.php",         "Critical 🔴", "WordPress config — may contain DB credentials"),
    ("/wp-config.php.bak",     "Critical 🔴", "WordPress config backup"),
    ("/.DS_Store",             "Low 🔵",      "macOS metadata file"),
    ("/crossdomain.xml",       "Low 🔵",      "Flash cross-domain policy"),
    ("/server-status",         "Medium 🟡",   "Apache server status page"),
    ("/elmah.axd",             "High 🟠",     "ASP.NET error log"),
    ("/trace.axd",             "High 🟠",     "ASP.NET trace viewer"),
]


def test_files(url, timeout=5):
    """
    Checks for exposed sensitive files.
    Returns list of findings.
    """
    findings = []
    base = url.rstrip("/")

    for path, severity, description in SENSITIVE_FILES:
        target = base + path
        try:
            response = requests.get(
                target, timeout=timeout,
                verify=False, allow_redirects=False
            )
            if response.status_code == 200 and len(response.content) > 0:
                findings.append({
                    "type": "Sensitive File Exposed",
                    "severity": severity,
                    "param": "-",
                    "payload": path,
                    "url": target,
                    "evidence": description
                })
        except Exception:
            continue

    return findings
