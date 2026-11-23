"""Data governance — local secret vault, redaction, and the audit/ack log.

Secrets never reach the LLM (vault + redaction), and every engagement is
authorized and auditable (hash-chained audit log + authorization ack).
"""
from .audit import Acknowledgement, AuditLog
from .redaction import Redactor
from .vault import PLACEHOLDER_RE, Vault

__all__ = ["Vault", "Redactor", "PLACEHOLDER_RE", "AuditLog", "Acknowledgement"]
