"""Applicability Gate — "does this project even have the surface for this
vulnerability class?" (P-A2).

Inspired by the Codebuddy Security benchmark study
(docs/ai/benchmark-vs-codebuddy.md, P-A2 "Gate 适用性门控"): before spending
audit budget on a vulnerability class, check whether the project has the
prerequisite surface (no auth mechanism anywhere → broken-auth/IDOR auditing
is pure noise; no HTTP surface at all → web classes are moot). Not-applicable
classes are cut from agent audit focus, semgrep rule selection, and routed to
a review queue instead of the report.

Design principles
-----------------
- **Deterministic, no LLM**: three cheap signal sources — the L1 attack
  surface report, the tech-stack summary dict, and a bounded static probe
  (file names + import lines, ≤ ``PROBE_MAX_FILES`` files).
- **Fail-open**: any uncertain class stays applicable. A class is only gated
  with explicit negative evidence AND confidence ≥ ``GATE_CONFIDENCE_THRESHOLD``
  (mirrors ``RuleGatingEngine``'s fail-open philosophy — 宁可多查不漏报).
- **Single convergence point with rule gating**: consumers merge
  ``GateReport.disabled_rule_keywords()`` into the existing RuleGating
  exclusion list; the gate never maintains a second gating mechanism.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger

logger = get_logger(__name__)

#: A class is only "not applicable" (gated) at or above this confidence.
GATE_CONFIDENCE_THRESHOLD = 0.7

#: Upper bound on files probed — the gate must stay cheap on big repos.
PROBE_MAX_FILES = 500

#: Max bytes read per probed file (imports live near the top).
PROBE_MAX_BYTES = 64 * 1024

#: Source extensions worth probing (mirror of common project languages).
_PROBE_EXTENSIONS = {
    ".py", ".go", ".java", ".js", ".jsx", ".ts", ".tsx",
    ".rb", ".php", ".cs", ".kt", ".scala",
}

#: Directories never worth probing (build artifacts / vendored code).
_PROBE_SKIP_DIRS = {
    "node_modules", "venv", ".venv", "env", "__pycache__", ".git",
    "dist", "build", "target", "out", "vendor", "third_party",
    "migrations", "docs", "tests", "test", "spec", ".idea", ".vscode",
}


# ---------------------------------------------------------------------------
# Signals
# ---------------------------------------------------------------------------


@dataclass
class GateSignals:
    """Everything the gate knows about the project, flattened."""

    # Whether attack-surface data was available at all. "No report" is NOT
    # evidence of "no surface" (e.g. resume runs where L1 was skipped) —
    # classes whose negative verdict would rest on missing data must fail
    # open to uncertain.
    attack_surface_available: bool = False

    # Attack-surface-derived
    has_http: bool = False
    total_http: int = 0
    unauthenticated_http: int = 0
    authenticated_endpoints: int = 0
    auth_middleware_hits: list[str] = field(default_factory=list)
    has_file_inputs: bool = False
    has_mq: bool = False
    has_cron: bool = False
    has_websocket: bool = False
    frameworks: list[str] = field(default_factory=list)

    # Tech-stack-derived
    databases: list[str] = field(default_factory=list)

    # Static-probe-derived (probe name → hit count)
    probe_hits: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_surface_available": self.attack_surface_available,
            "has_http": self.has_http,
            "total_http": self.total_http,
            "unauthenticated_http": self.unauthenticated_http,
            "authenticated_endpoints": self.authenticated_endpoints,
            "auth_middleware_hits": self.auth_middleware_hits,
            "has_file_inputs": self.has_file_inputs,
            "has_mq": self.has_mq,
            "has_cron": self.has_cron,
            "has_websocket": self.has_websocket,
            "frameworks": self.frameworks,
            "databases": self.databases,
            "probe_hits": dict(self.probe_hits),
        }


_AUTH_NAME_RE = re.compile(
    r"(login|logon|auth|session|jwt|token|permission|rbac|identity|oauth)", re.I
)
_AUTH_CONTENT_RE = re.compile(
    r"(flask_login|login_required|jwt|passlib|springframework\.security"
    r"|passport|express-session|koa-session|devise|omniauth"
    r"|middleware.*auth|UseAuthentication|UseAuthorization|@RequiresPermissions)",
    re.I,
)
_UPLOAD_NAME_RE = re.compile(r"(upload|attachment)", re.I)
_UPLOAD_CONTENT_RE = re.compile(
    r"(UploadFile|multer|MultipartFile|upload_handler|file\.save|save_file)",
    re.I,
)
_CRYPTO_CONTENT_RE = re.compile(
    r"(hashlib|Crypto\.|javax\.crypto|MessageDigest|crypto/(md5|sha1|aes)"
    r"|\bmd5\b|\bsha1\b|\bsha256\b|bcrypt)",
    re.I,
)
_SQL_CONTENT_RE = re.compile(
    r"(database/sql|sql\.Open|sqlalchemy|\bcursor\(|JdbcTemplate|gorm\.Open"
    r"|pymysql|psycopg|sqlite3|jdbc|sequelize|typeorm|knex\()",
    re.I,
)
_DESER_CONTENT_RE = re.compile(
    r"(pickle|yaml\.load|ObjectInputStream|XMLDecoder|unserialize"
    r"|gob\.NewDecoder|xml\.Unmarshal|marshal\.loads|readObject)",
    re.I,
)
_XML_CONTENT_RE = re.compile(
    r"(xml\.etree|lxml|encoding/xml|javax\.xml|DocumentBuilder|Unmarshaller"
    r"|defusedxml|xml\.NewDecoder)",
    re.I,
)

_PROBES: dict[str, tuple[re.Pattern[str] | None, re.Pattern[str]]] = {
    # probe name: (file/directory-name regex or None, content regex)
    "auth": (_AUTH_NAME_RE, _AUTH_CONTENT_RE),
    "upload": (_UPLOAD_NAME_RE, _UPLOAD_CONTENT_RE),
    "crypto": (None, _CRYPTO_CONTENT_RE),
    "sql": (None, _SQL_CONTENT_RE),
    "deserialization": (None, _DESER_CONTENT_RE),
    "xml": (None, _XML_CONTENT_RE),
}


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


@dataclass
class GateDecision:
    """Applicability verdict for one vulnerability class.

    ``applicable is None`` means *uncertain* — consumers must treat it as
    applicable (fail-open). Only ``applicable is False`` with
    ``confidence >= GATE_CONFIDENCE_THRESHOLD`` counts as gated.
    """

    vuln_class: str
    applicable: bool | None
    confidence: float
    reason: str
    evidence: list[str] = field(default_factory=list)

    @property
    def is_gated(self) -> bool:
        return (
            self.applicable is False
            and self.confidence >= GATE_CONFIDENCE_THRESHOLD
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "vuln_class": self.vuln_class,
            "applicable": self.applicable,
            "confidence": self.confidence,
            "reason": self.reason,
            "evidence": self.evidence,
            "gated": self.is_gated,
        }


class GateReport:
    """Verdicts for every known vulnerability class."""

    def __init__(self, decisions: list[GateDecision], signals: GateSignals | None = None):
        self.decisions = decisions
        self.signals = signals

    def decision_for(self, vuln_class: str) -> GateDecision | None:
        for d in self.decisions:
            if d.vuln_class == vuln_class:
                return d
        return None

    def gated_classes(self) -> list[str]:
        """Classes with explicit, high-confidence negative evidence."""
        return [d.vuln_class for d in self.decisions if d.is_gated]

    def disabled_rule_keywords(self) -> list[str]:
        """Semgrep rule-id keywords to merge into the RuleGating exclusion list."""
        keywords: list[str] = []
        for cls in self.gated_classes():
            keywords.extend(CLASS_RULE_KEYWORDS.get(cls, ()))
        return sorted(set(keywords))

    def to_summary(self) -> dict[str, Any]:
        return {
            "decisions": [d.to_dict() for d in self.decisions],
            "gated_classes": self.gated_classes(),
            "signals": self.signals.to_dict() if self.signals else None,
        }


#: Keyword fragments used to (a) disable matching semgrep rule ids for gated
#: classes and (b) recognize gated-class findings by their ``rule_id``.
CLASS_RULE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "sqli": ("sqli", "sql-injection", "sql_injection", "tainted-sql"),
    "xss": ("xss", "cross-site-scripting", "cross_site_scripting"),
    "ssrf": ("ssrf", "server-side-request-forgery", "tainted-url"),
    "command_injection": (
        "command-injection", "command_injection", "cmd-injection", "cmdi",
        "dangerous-exec", "tainted-cmd", "shell-injection",
    ),
    "path_traversal": (
        "path-traversal", "path_traversal", "directory-traversal",
    ),
    "authn_bypass": ("broken-auth", "authentication", "auth-bypass"),
    "authz_idor": ("idor", "access-control", "authorization", "authz"),
    "deserialization": ("deserialization", "deserial", "unsafe-pickle"),
    "crypto_misuse": ("crypto", "weak-hash", "insecure-hash", "md5", "sha1"),
    "file_upload": ("file-upload", "upload"),
    "xxe": ("xxe", "xml-external-entity"),
    "open_redirect": ("open-redirect", "open_redirect", "url-redirect"),
}


def finding_matches_gated_class(rule_id: str | None, gated_classes: list[str]) -> str | None:
    """Return the gated class a finding's ``rule_id`` belongs to, if any.

    ``rule_id`` doubles as the vulnerability class for agent findings
    (``sql_injection``) and as the engine rule id for semgrep
    (``go.lang.security...sql-injection``); keyword matching covers both.
    Returns None when the finding's class is not gated.
    """
    if not rule_id or not gated_classes:
        return None
    rid = rule_id.lower().replace("_", "-")
    for cls in gated_classes:
        for kw in CLASS_RULE_KEYWORDS.get(cls, ()):
            if kw in rid or rid in kw:
                return cls
    return None


# ---------------------------------------------------------------------------
# The gate itself
# ---------------------------------------------------------------------------


class ApplicabilityGate:
    """Evaluates per-class applicability from cheap deterministic signals."""

    def __init__(
        self,
        tech_stack: dict[str, Any] | None = None,
        attack_surface: Any | None = None,
        source_path: Path | None = None,
        enable_probes: bool = True,
    ) -> None:
        self.tech_stack = tech_stack or {}
        self.attack_surface = attack_surface
        self.source_path = source_path
        self.enable_probes = enable_probes and source_path is not None
        self.logger = get_logger(__name__)

    # -- public API ---------------------------------------------------------

    def evaluate(self) -> GateReport:
        signals = self._collect_signals()
        decisions = [
            self._decide_sqli(signals),
            self._decide_xss(signals),
            self._decide_ssrf(signals),
            self._decide_open_redirect(signals),
            self._decide_xxe(signals),
            self._decide_cmdi(signals),
            self._decide_path_traversal(signals),
            self._decide_authn_bypass(signals),
            self._decide_authz_idor(signals),
            self._decide_deserialization(signals),
            self._decide_crypto_misuse(signals),
            self._decide_file_upload(signals),
        ]
        gated = [d.vuln_class for d in decisions if d.is_gated]
        self.logger.info(
            f"Applicability gate: {len(gated)} gated class(es) "
            f"({', '.join(gated) if gated else 'none'}); "
            f"probes={signals.probe_hits or '{}'}"
        )
        return GateReport(decisions, signals)

    # -- signal collection --------------------------------------------------

    def _collect_signals(self) -> GateSignals:
        s = GateSignals()
        self._collect_attack_surface_signals(s)
        self._collect_tech_stack_signals(s)
        if self.enable_probes:
            s.probe_hits = self._run_probes()
        return s

    def _collect_attack_surface_signals(self, s: GateSignals) -> None:
        report = self.attack_surface
        if report is None:
            # No report ≠ no surface (resume / detection-skipped): fail open.
            s.attack_surface_available = False
            return
        s.attack_surface_available = True
        # Accept both the pydantic report and a plain dict-shaped stand-in.
        entry_points = getattr(report, "entry_points", None) or []
        for ep in entry_points:
            etype = getattr(ep, "type", None)
            etype_val = getattr(etype, "value", etype)
            if etype_val == "http":
                s.total_http += 1
                if getattr(ep, "auth_required", False):
                    s.authenticated_endpoints += 1
            elif etype_val == "mq":
                s.has_mq = True
            elif etype_val == "cron":
                s.has_cron = True
            elif etype_val == "websocket":
                s.has_websocket = True
            elif etype_val == "file":
                s.has_file_inputs = True
            for mw in getattr(ep, "middleware", None) or []:
                if _AUTH_NAME_RE.search(str(mw)) and str(mw) not in s.auth_middleware_hits:
                    s.auth_middleware_hits.append(str(mw))
        s.has_http = s.total_http > 0
        s.unauthenticated_http = max(0, s.total_http - s.authenticated_endpoints)
        frameworks = getattr(report, "frameworks_detected", None) or []
        s.frameworks = [str(f) for f in frameworks]

    def _collect_tech_stack_signals(self, s: GateSignals) -> None:
        ts = self.tech_stack
        if not ts:
            return
        get = ts.get if isinstance(ts, dict) else lambda k, d=None: getattr(ts, k, d)
        s.databases = [str(db) for db in (get("databases") or [])]
        for fw in get("frameworks") or []:
            fw = str(fw)
            if fw not in s.frameworks:
                s.frameworks.append(fw)
        for mw in get("middleware") or []:
            if _AUTH_NAME_RE.search(str(mw)) and str(mw) not in s.auth_middleware_hits:
                s.auth_middleware_hits.append(str(mw))

    def _run_probes(self) -> dict[str, int]:
        """Bounded filename + import-line probe. Never raises."""
        hits: dict[str, int] = {name: 0 for name in _PROBES}
        if not self.source_path or not Path(self.source_path).exists():
            return hits
        root = Path(self.source_path)
        scanned = 0
        try:
            for path in sorted(root.rglob("*")):
                if scanned >= PROBE_MAX_FILES:
                    break
                if not path.is_file() or path.suffix.lower() not in _PROBE_EXTENSIONS:
                    continue
                rel_parts = path.relative_to(root).parts
                if any(part in _PROBE_SKIP_DIRS for part in rel_parts):
                    continue
                # Filename signal (auth / upload probes only)
                if _PROBES["auth"][0] and _PROBES["auth"][0].search(path.name):
                    hits["auth"] += 1
                if _PROBES["upload"][0] and _PROBES["upload"][0].search(path.name):
                    hits["upload"] += 1
                # Content signal
                try:
                    text = path.read_text(encoding="utf-8", errors="ignore")[
                        :PROBE_MAX_BYTES
                    ]
                except OSError:
                    continue
                scanned += 1
                for name, (_, content_re) in _PROBES.items():
                    if name in hits and hits[name] == 0 and content_re.search(text):
                        hits[name] += 1
        except Exception as e:  # noqa: BLE001 — probe is best-effort
            self.logger.warning(f"Applicability gate probe failed (fail-open): {e}")
        return hits

    # -- per-class decisions -------------------------------------------------

    @staticmethod
    def _decide(
        vuln_class: str,
        applicable: bool | None,
        confidence: float,
        reason: str,
        evidence: list[str] | None = None,
    ) -> GateDecision:
        # Fail-open: weak evidence never gates a class shut.
        if applicable is False and confidence < GATE_CONFIDENCE_THRESHOLD:
            applicable = None
            reason = f"low-confidence negative demoted to uncertain: {reason}"
        return GateDecision(vuln_class, applicable, confidence, reason, evidence or [])

    def _decide_sqli(self, s: GateSignals) -> GateDecision:
        evidence = list(s.databases)
        if s.probe_hits.get("sql"):
            evidence.append("sql probe hit")
        if evidence:
            return self._decide("sqli", True, 0.85, "database/SQL surface present", evidence)
        return self._decide("sqli", False, 0.75, "no database configured and no SQL usage probed")

    def _decide_xss(self, s: GateSignals) -> GateDecision:
        if s.has_http or s.has_websocket:
            return self._decide("xss", True, 0.9, "HTTP/WebSocket surface present")
        if not s.attack_surface_available:
            return self._decide("xss", None, 0.0, "no attack surface data — fail-open")
        return self._decide("xss", False, 0.85, "no HTTP/WebSocket entry points")

    def _decide_ssrf(self, s: GateSignals) -> GateDecision:
        if s.has_http:
            return self._decide("ssrf", True, 0.9, "HTTP surface present")
        if not s.attack_surface_available:
            return self._decide("ssrf", None, 0.0, "no attack surface data — fail-open")
        return self._decide("ssrf", False, 0.85, "no HTTP entry points")

    def _decide_open_redirect(self, s: GateSignals) -> GateDecision:
        if s.has_http:
            return self._decide("open_redirect", True, 0.9, "HTTP surface present")
        if not s.attack_surface_available:
            return self._decide("open_redirect", None, 0.0, "no attack surface data — fail-open")
        return self._decide("open_redirect", False, 0.85, "no HTTP entry points")

    def _decide_xxe(self, s: GateSignals) -> GateDecision:
        if s.probe_hits.get("xml"):
            return self._decide("xxe", True, 0.85, "XML parsing probed")
        if not s.attack_surface_available:
            return self._decide("xxe", None, 0.0, "no attack surface data — fail-open")
        if not s.has_http:
            return self._decide("xxe", False, 0.85, "no HTTP surface and no XML usage probed")
        return self._decide("xxe", None, 0.0, "no XML probed but HTTP exists — fail-open")

    @staticmethod
    def _decide_cmdi(s: GateSignals) -> GateDecision:
        return GateDecision("command_injection", True, 0.9, "no prerequisite surface required")

    def _decide_path_traversal(self, s: GateSignals) -> GateDecision:
        if s.has_http or s.has_file_inputs:
            return self._decide("path_traversal", True, 0.8, "HTTP/file input surface present")
        if not s.attack_surface_available:
            return self._decide("path_traversal", None, 0.0, "no attack surface data — fail-open")
        return self._decide("path_traversal", False, 0.75, "no HTTP or file input entry points")

    def _decide_authn_bypass(self, s: GateSignals) -> GateDecision:
        return self._decide_auth_class("authn_bypass", s)

    def _decide_authz_idor(self, s: GateSignals) -> GateDecision:
        return self._decide_auth_class("authz_idor", s)

    def _decide_auth_class(self, cls: str, s: GateSignals) -> GateDecision:
        evidence: list[str] = []
        if s.auth_middleware_hits:
            evidence.append(f"auth middleware: {s.auth_middleware_hits[:3]}")
        if s.authenticated_endpoints:
            evidence.append(f"{s.authenticated_endpoints} auth-required endpoint(s)")
        if s.probe_hits.get("auth"):
            evidence.append("auth probe hit")
        if evidence:
            return self._decide(cls, True, 0.85, "authentication/authorization surface present", evidence)
        if not s.attack_surface_available:
            return self._decide(cls, None, 0.0, "no attack surface data — fail-open")
        if not s.has_http:
            return self._decide(cls, False, 0.9, "no HTTP surface at all")
        # The Codebuddy Gate case: a web project with zero auth mechanism —
        # there is nothing to bypass, so auth auditing is pure noise.
        return self._decide(cls, False, 0.75, "HTTP present but no auth mechanism signaled")

    def _decide_deserialization(self, s: GateSignals) -> GateDecision:
        evidence: list[str] = []
        if s.probe_hits.get("deserialization"):
            evidence.append("deserialization probe hit")
        if s.has_mq:
            evidence.append("MQ consumers present")
        if evidence:
            return self._decide("deserialization", True, 0.8, "deserialization surface present", evidence)
        # Probe evidence is independent of the attack-surface report — a
        # negative probe verdict stays valid even when surface data is absent.
        return self._decide("deserialization", False, 0.72, "no deserialization API probed")

    def _decide_crypto_misuse(self, s: GateSignals) -> GateDecision:
        if s.probe_hits.get("crypto"):
            return self._decide("crypto_misuse", True, 0.85, "crypto API probed")
        return self._decide("crypto_misuse", False, 0.75, "no crypto API probed")

    def _decide_file_upload(self, s: GateSignals) -> GateDecision:
        evidence: list[str] = []
        if s.has_file_inputs:
            evidence.append("file input entry points")
        if s.probe_hits.get("upload"):
            evidence.append("upload probe hit")
        if evidence:
            return self._decide("file_upload", True, 0.85, "upload surface present", evidence)
        if not s.attack_surface_available:
            return self._decide("file_upload", None, 0.0, "no attack surface data — fail-open")
        if not s.has_http:
            return self._decide("file_upload", False, 0.8, "no HTTP surface and no upload signal")
        return self._decide("file_upload", None, 0.0, "HTTP exists but no upload signal — fail-open")


def evaluate_applicability(
    tech_stack: dict[str, Any] | None = None,
    attack_surface: Any | None = None,
    source_path: Path | None = None,
) -> GateReport:
    """Convenience entry point used by the orchestrator."""
    return ApplicabilityGate(
        tech_stack=tech_stack,
        attack_surface=attack_surface,
        source_path=source_path,
    ).evaluate()
