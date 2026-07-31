import requests

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/administrator", "/administrator/", "/administrator/index.php",
    "/wp-admin", "/wp-admin/", "/wp-login.php",
    "/login", "/login.php", "/login.html",
    "/dashboard", "/dashboard/",
    "/panel", "/panel/",
    "/cpanel", "/cPanel/",
    "/webmail", "/webmail/",
    "/phpmyadmin", "/phpmyadmin/",
    "/adminer", "/adminer.php",
    "/manager", "/manager/",
    "/controlpanel", "/control-panel/",
    "/user/login", "/users/login",
    "/auth", "/auth/login",
    "/backend", "/backend/",
    "/secure", "/secure/login",
    "/moderator", "/moderator/",
    "/superadmin", "/super-admin/",
]


def test_admin(url, timeout=5):
    """
    Checks for exposed admin panels.
    Returns list of findings.
    """
    findings = []
    base = url.rstrip("/")

    for path in ADMIN_PATHS:
        target = base + path
        try:
            response = requests.get(
                target, timeout=timeout,
                verify=False, allow_redirects=False
            )
            if response.status_code in [200, 401, 403]:
                severity = "High 🟠" if response.status_code == 200 else "Medium 🟡"
                findings.append({
                    "type": "Admin Panel Found",
                    "severity": severity,
                    "param": "-",
                    "payload": path,
                    "url": target,
                    "evidence": f"Status: {response.status_code}"
                })
        except Exception:
            continue

    return findings
