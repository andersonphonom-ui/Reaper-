import requests

SECURITY_HEADERS = {
    "Content-Security-Policy":         ("High 🟠",    "Protects against XSS and injection attacks"),
    "X-Frame-Options":                 ("Medium 🟡",  "Protects against Clickjacking"),
    "X-Content-Type-Options":          ("Medium 🟡",  "Prevents MIME-type sniffing"),
    "Strict-Transport-Security":       ("High 🟠",    "Enforces HTTPS connections"),
    "Referrer-Policy":                 ("Low 🔵",     "Controls referrer information"),
    "Permissions-Policy":              ("Low 🔵",     "Controls browser features access"),
    "X-XSS-Protection":               ("Medium 🟡",  "Legacy XSS filter for older browsers"),
    "Cross-Origin-Opener-Policy":      ("Low 🔵",     "Isolates browsing context"),
    "Cross-Origin-Resource-Policy":    ("Low 🔵",     "Controls cross-origin resource sharing"),
}

DANGEROUS_HEADERS = {
    "Server":       "Reveals server software version",
    "X-Powered-By": "Reveals backend technology",
    "X-AspNet-Version": "Reveals ASP.NET version",
}


def test_headers(url, timeout=5):
    """
    Checks for missing security headers and information disclosure.
    Returns list of findings.
    """
    findings = []

    try:
        response = requests.get(url, timeout=timeout, verify=False)
        headers = response.headers
    except Exception:
        return findings

    # Missing security headers
    for header, (severity, description) in SECURITY_HEADERS.items():
        if header not in headers:
            findings.append({
                "type": f"Missing Header: {header}",
                "severity": severity,
                "param": "-",
                "payload": "-",
                "url": url,
                "evidence": description
            })

    # Dangerous headers
    for header, description in DANGEROUS_HEADERS.items():
        if header in headers:
            findings.append({
                "type": f"Information Disclosure: {header}",
                "severity": "Low 🔵",
                "param": "-",
                "payload": "-",
                "url": url,
                "evidence": f"{header}: {headers[header]} — {description}"
            })

    return findings
