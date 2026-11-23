"""Vulnerability classes (CVSS 3.1, OWASP/CWE, detection and remediation text)
and the signatures detectors match against.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class VulnClass:
    id: str
    title: str
    cvss_score: float
    cvss_vector: str
    owasp: str
    cwe: str
    detection_guidance: str      # 🔵 how the blue team detects it
    remediation: str             # 🔵 how to fix it


VULN_CLASSES: dict[str, VulnClass] = {
    # web
    "sqli": VulnClass(
        "sqli", "SQL Injection", 9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "A03:2021-Injection", "CWE-89",
        "Alert on DB errors in responses, anomalous query latency, and WAF rules "
        "matching tautologies/UNION in parameters; review ORM/raw-SQL usage.",
        "Use parameterized queries / prepared statements; validate and allow-list "
        "input; least-privilege DB accounts; disable verbose SQL errors."),
    "xss_reflected": VulnClass(
        "xss_reflected", "Reflected Cross-Site Scripting", 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "A03:2021-Injection", "CWE-79",
        "Monitor for script-like payloads reflected in responses; CSP violation "
        "reports; WAF signatures for <script>/onerror in parameters.",
        "Context-aware output encoding; a strict Content-Security-Policy; validate "
        "input; use framework auto-escaping."),
    "security_misconfig": VulnClass(
        "security_misconfig", "Security Misconfiguration (missing headers)", 4.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "A05:2021-Security Misconfiguration", "CWE-16",
        "Baseline expected security headers and alert on drift via periodic header "
        "scans.",
        "Set CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy; "
        "harden defaults; disable directory listing and verbose errors."),
    "sensitive_file": VulnClass(
        "sensitive_file", "Sensitive File Exposure", 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A05:2021-Security Misconfiguration", "CWE-538",
        "Alert on access to dotfiles/backups (/.env, /.git, *.bak) in web logs; "
        "file-integrity monitoring on the web root.",
        "Remove secrets/backups from the web root; block dotfiles and archive "
        "extensions at the server; rotate any exposed secret."),
    "cookie_flags": VulnClass(
        "cookie_flags", "Insecure Cookie Flags", 4.3,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "A05:2021-Security Misconfiguration", "CWE-614",
        "Inspect Set-Cookie attributes in traffic; alert on session cookies "
        "lacking HttpOnly/Secure.",
        "Set HttpOnly, Secure, and SameSite on session cookies; scope Path/Domain "
        "tightly."),
    "open_redirect": VulnClass(
        "open_redirect", "Open Redirect", 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "A01:2021-Broken Access Control", "CWE-601",
        "Watch for off-site hosts in redirect parameters and Location headers.",
        "Allow-list redirect targets; use relative paths or signed tokens, never "
        "raw user-supplied URLs."),
    # network / server
    "dom_xss": VulnClass(
        "dom_xss", "DOM-based Cross-Site Scripting", 6.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "A03:2021-Injection", "CWE-79",
        "CSP violation reports (require-trusted-types-for 'script'); client-side error monitoring for "
        "unexpected DOM nodes; review uses of innerHTML/document.write/eval on URL-derived data.",
        "Never write URL, hash or storage data into innerHTML/document.write; use textContent or a "
        "sanitizer (DOMPurify); enforce Trusted Types and a strict CSP."),
    "sensitive_client_storage": VulnClass(
        "sensitive_client_storage", "Sensitive Data in Browser Storage", 5.3,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N", "A04:2021-Insecure Design", "CWE-922",
        "Client-side audits of localStorage/sessionStorage keys; flag tokens readable by any script "
        "on the origin (one XSS steals them).",
        "Keep session tokens in HttpOnly, Secure, SameSite cookies; never store secrets or long-lived "
        "tokens in localStorage/sessionStorage."),
    "vulnerable_js_library": VulnClass(
        "vulnerable_js_library", "Vulnerable JavaScript Library", 6.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "A06:2021-Vulnerable and Outdated Components",
        "CWE-1104",
        "Software composition analysis of front-end bundles in CI (npm audit, retire.js); alert on "
        "known-vulnerable versions served in production.",
        "Upgrade the library to a fixed release; remove unused libraries; pin and audit dependencies."),
    "exposed_source_map": VulnClass(
        "exposed_source_map", "Exposed JavaScript Source Map", 3.7,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", "A05:2021-Security Misconfiguration", "CWE-540",
        "Alert on requests for *.map files in web logs; scan deployments for published source maps.",
        "Do not deploy .map files to production (or restrict them to internal networks)."),
    "weak_csp": VulnClass(
        "weak_csp", "Weak Content-Security-Policy", 4.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
        "A05:2021-Security Misconfiguration", "CWE-693",
        "Collect CSP violation reports (report-to); lint policies for unsafe-inline, unsafe-eval and "
        "wildcard sources.",
        "Remove 'unsafe-inline' and 'unsafe-eval'; use nonces or hashes for scripts; avoid wildcards; "
        "add object-src 'none' and base-uri 'self'."),
    "cors_misconfig": VulnClass(
        "cors_misconfig", "Permissive CORS with Credentials", 6.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "A05:2021-Security Misconfiguration", "CWE-942",
        "Alert on responses that echo arbitrary Origin values together with "
        "Access-Control-Allow-Credentials: true.",
        "Allow-list exact trusted origins; never reflect the request Origin when credentials are allowed."),
    "info_leak_console": VulnClass(
        "info_leak_console", "Information Leak in Browser Console", 2.6,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", "A05:2021-Security Misconfiguration", "CWE-209",
        "Front-end error monitoring for stack traces and internal paths logged in production builds.",
        "Strip debug logging from production bundles; report errors to a backend collector instead of "
        "the console."),
    "secret_in_client_code": VulnClass(
        "secret_in_client_code", "Secret Exposed in Client-Side Code", 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", "A02:2021-Cryptographic Failures", "CWE-798",
        "Secret scanning of built front-end assets in CI; watch provider logs for use of the leaked key.",
        "Revoke and rotate the key; move it to a backend that proxies the call; never ship secrets to "
        "the browser."),
    "mixed_content": VulnClass(
        "mixed_content", "Mixed Content", 4.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
        "A02:2021-Cryptographic Failures", "CWE-319",
        "Browser CSP reports (block-all-mixed-content / upgrade-insecure-requests); crawl for http:// "
        "subresources on https pages.",
        "Load every subresource over HTTPS; add upgrade-insecure-requests to the CSP."),
    "template_finding": VulnClass(
        "template_finding", "Template-detected issue", 5.3, "",
        "A05:2021-Security Misconfiguration", "CWE-1035",
        "Alert on the request pattern the matching template uses (see evidence); add the "
        "template to scheduled scans so regressions are caught.",
        "Apply the vendor fix or configuration change named in the finding; re-run the "
        "template to confirm it no longer matches."),
    "exposed_service": VulnClass(
        "exposed_service", "Unauthenticated Exposed Service", 9.1,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "A05:2021-Security Misconfiguration", "CWE-306",
        "Alert on datastore/admin ports reachable from untrusted networks; netflow "
        "egress/ingress review.",
        "Bind services to localhost/VPN; require authentication; firewall the "
        "management ports; segment the network."),
    "cleartext_service": VulnClass(
        "cleartext_service", "Cleartext Service Exposed", 5.9,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A02:2021-Cryptographic Failures", "CWE-319",
        "Flag plaintext protocols (telnet/ftp/http) on sensitive hosts in traffic.",
        "Replace with TLS equivalents (SSH/FTPS/HTTPS); disable the cleartext "
        "listener."),
    "exposed_panel": VulnClass(
        "exposed_panel", "Exposed Management Panel", 7.3,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "A05:2021-Security Misconfiguration", "CWE-284",
        "Monitor access to admin paths from the internet; geofence/allow-list "
        "management UIs.",
        "Restrict admin panels to VPN/allow-listed IPs; add authentication and MFA; "
        "rename default paths is not sufficient alone."),
    "weak_tls": VulnClass(
        "weak_tls", "Weak / Invalid TLS", 5.9,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A02:2021-Cryptographic Failures", "CWE-326",
        "Continuous TLS scanning for protocol/cipher/cert drift and expiry.",
        "Disable TLS<1.2; renew/replace expired or self-signed certs; enable HSTS; "
        "use strong cipher suites."),
    "outdated_software": VulnClass(
        "outdated_software", "Outdated Software (version)", 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "A06:2021-Vulnerable and Outdated Components", "CWE-1104",
        "Inventory software versions from banners; correlate with CVE feeds.",
        "Patch to a supported release; remove version banners; track components in "
        "an SBOM."),
    # mobile
    "mobile_secret": VulnClass(
        "mobile_secret", "Hardcoded Secret in App", 7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "MASVS-STORAGE", "CWE-798",
        "Scan build artifacts/APKs for secret patterns in CI; secret-scanning on "
        "repos.",
        "Remove secrets from the app; use a backend broker / remote config; rotate "
        "exposed keys; apply key restrictions."),
    "mobile_cleartext": VulnClass(
        "mobile_cleartext", "Cleartext Traffic Allowed", 5.9,
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "MASVS-NETWORK", "CWE-319",
        "Review network-security-config and usesCleartextTraffic in app builds.",
        "Set usesCleartextTraffic=false; enforce HTTPS; pin certificates where "
        "appropriate."),
    "mobile_exported": VulnClass(
        "mobile_exported", "Exported Component", 6.3,
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
        "MASVS-PLATFORM", "CWE-926",
        "Audit the manifest for exported components lacking permissions.",
        "Set exported=false unless required; protect with signature-level "
        "permissions; validate all IPC input."),
    "mobile_weak_crypto": VulnClass(
        "mobile_weak_crypto", "Weak Cryptography", 5.9,
        "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "MASVS-CRYPTO", "CWE-327",
        "Static analysis for ECB/MD5/SHA1/DES and hardcoded IV/keys in builds.",
        "Use AES-GCM, SHA-256+, random IVs, and the platform keystore; drop "
        "ECB/DES/MD5/SHA1 for security."),
    "mobile_debuggable": VulnClass(
        "mobile_debuggable", "Debuggable Build", 5.0,
        "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
        "MASVS-RESILIENCE", "CWE-489",
        "Reject debuggable builds in release pipelines.",
        "Set android:debuggable=false for release builds."),
}

# domain → the classes that apply (for the coverage checklist)
DOMAIN_CLASSES: dict[str, list[str]] = {
    "web": ["sqli", "xss_reflected", "security_misconfig", "sensitive_file",
            "cookie_flags", "open_redirect"],
    "network": ["exposed_service", "cleartext_service", "outdated_software"],
    "server": ["weak_tls", "security_misconfig", "exposed_panel", "outdated_software"],
    "mobile": ["mobile_secret", "mobile_cleartext", "mobile_exported",
               "mobile_weak_crypto", "mobile_debuggable"],
}


def cls(class_id: str) -> VulnClass:
    return VULN_CLASSES[class_id]


# DB error fingerprints → (engine) for error-based SQLi detection.
SQL_ERRORS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"you have an error in your sql syntax", re.I), "MySQL"),
    (re.compile(r"warning:\s+mysqli?_", re.I), "MySQL"),
    (re.compile(r"unclosed quotation mark after the character string", re.I), "MSSQL"),
    (re.compile(r"quoted string not properly terminated", re.I), "Oracle"),
    (re.compile(r"pg_query\(\)|unterminated quoted string|PostgreSQL.*ERROR", re.I), "PostgreSQL"),
    (re.compile(r"sqlite3?::|SQLITE_ERROR|unrecognized token", re.I), "SQLite"),
    (re.compile(r"SQL syntax.*MariaDB", re.I), "MariaDB"),
]

# Sensitive paths probed with a safe GET; value = a content signature confirming it.
SENSITIVE_FILES: list[tuple[str, re.Pattern]] = [
    ("/.env", re.compile(r"(?mi)^[A-Z0-9_]+=.+")),
    ("/.git/config", re.compile(r"\[core\]|\[remote ", re.I)),
    ("/.git/HEAD", re.compile(r"ref:\s*refs/", re.I)),
    ("/config.php.bak", re.compile(r"<\?php|db_pass|define\(", re.I)),
    ("/backup.zip", re.compile(r"PK\x03\x04")),
    ("/.DS_Store", re.compile(r"Bud1", re.I)),
    ("/phpinfo.php", re.compile(r"PHP Version|phpinfo\(\)", re.I)),
    ("/.aws/credentials", re.compile(r"aws_access_key_id", re.I)),
]

# Common management panels (safe GET; value = signature in body).
ADMIN_PANELS: list[tuple[str, re.Pattern]] = [
    ("/admin", re.compile(r"login|admin|dashboard", re.I)),
    ("/manager/html", re.compile(r"Tomcat|Manager", re.I)),
    ("/phpmyadmin", re.compile(r"phpMyAdmin", re.I)),
    ("/actuator", re.compile(r'"_links"|health|env', re.I)),
    ("/server-status", re.compile(r"Apache Server Status", re.I)),
    ("/.git/", re.compile(r"Index of|HEAD|config", re.I)),
]

# port → (class_id, service, needs_safe_proto_check)
RISKY_SERVICES: dict[int, tuple[str, str]] = {
    23: ("cleartext_service", "telnet"),
    21: ("cleartext_service", "ftp"),
    2375: ("exposed_service", "docker"),
    6379: ("exposed_service", "redis"),
    27017: ("exposed_service", "mongodb"),
    9200: ("exposed_service", "elasticsearch"),
    11211: ("exposed_service", "memcached"),
    5432: ("exposed_service", "postgres"),
    3306: ("exposed_service", "mysql"),
    1433: ("exposed_service", "mssql"),
    5900: ("exposed_service", "vnc"),
}
