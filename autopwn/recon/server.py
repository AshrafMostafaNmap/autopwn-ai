"""TLS posture: protocol, cipher, certificate validity, SAN, self-signed/expired."""
from __future__ import annotations

import socket
import ssl
from datetime import UTC, datetime

from .target_model import Service, Surface

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def tls_inspect(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    """Fetch and parse the server certificate + negotiated params. Read-only."""
    info: dict = {"host": host, "port": port}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE           # still inspect misconfigured hosts
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                info["protocol"] = ss.version()
                cipher = ss.cipher()
                info["cipher"] = cipher[0] if cipher else None
                der = ss.getpeercert(binary_form=True)
    except Exception as e:
        info["error"] = f"{type(e).__name__}: {e}"
        return info

    notes: list[str] = []
    if info.get("protocol") in _WEAK_PROTOCOLS:
        notes.append(f"weak TLS protocol negotiated: {info['protocol']}")

    # parse the certificate with `cryptography`
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        cert = x509.load_der_x509_certificate(der, default_backend())
        info["subject"] = cert.subject.rfc4514_string()
        info["issuer"] = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=UTC)
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=UTC)
        info["not_before"] = not_before.isoformat()
        info["not_after"] = not_after.isoformat()
        now = datetime.now(UTC)
        if not_after < now:
            notes.append(f"certificate EXPIRED on {not_after.date()}")
        if not_before > now:
            notes.append("certificate not yet valid")
        if cert.issuer == cert.subject:
            notes.append("certificate is self-signed")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            info["san"] = san.value.get_values_for_type(x509.DNSName)
        except Exception:
            info["san"] = []
    except Exception as e:
        info["cert_parse_error"] = str(e)

    info["notes"] = notes
    return info


def inspect(host: str, port: int = 443, *, timeout: float = 10.0) -> tuple[Surface, dict]:
    """Build a server/infra Surface from a TLS inspection."""
    surface = Surface(host=host, domain="server", scheme="https")
    tls = tls_inspect(host, port, timeout)
    surface.tls = tls
    if "error" in tls:
        surface.notes.append(f"TLS inspect failed on :{port}: {tls['error']}")
    else:
        surface.services.append(Service(port=port, name="https", version=tls.get("protocol", "")))
        surface.notes.extend(tls.get("notes", []))
        if tls.get("protocol"):
            surface.notes.append(f"TLS {tls['protocol']} · {tls.get('cipher')}")
    return surface, tls
