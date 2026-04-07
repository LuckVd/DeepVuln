"""JSONL output event types for structured logging.

This module defines all event types that can be emitted during a scan
when --output-format jsonl is enabled. Each event type corresponds to
a specific phase or action in the scanning process.

Event Format:
    {"type": "event_type", "timestamp": "ISO8601", ...event_specific_fields}
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from uuid import uuid4


class EventType(str, Enum):
    """All event types that can be emitted during a scan."""

    # Scan lifecycle
    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"

    # Phase lifecycle
    PHASE_START = "phase_start"
    PHASE_COMPLETE = "phase_complete"
    PHASE_FAILED = "phase_failed"
    PHASE_SKIPPED = "phase_skipped"

    # Engine events
    ENGINE_START = "engine_start"
    ENGINE_COMPLETE = "engine_complete"
    ENGINE_FAILED = "engine_failed"

    # File processing
    FILE_START = "file_start"
    FILE_COMPLETE = "file_complete"
    FILE_SKIPPED = "file_skipped"

    # Agent events
    AGENT_THINKING = "agent_thinking"
    AGENT_ACTION = "agent_action"
    AGENT_OBSERVATION = "agent_observation"

    # Adversarial verification
    ADVERSARIAL_START = "adversarial_start"
    ADVERSARIAL_ROUND = "adversarial_round"
    ADVERSARIAL_COMPLETE = "adversarial_complete"

    # Findings
    FINDING_NEW = "finding_new"
    FINDING_VERIFIED = "finding_verified"
    FINDING_FALSE_POSITIVE = "finding_false_positive"
    FINDING_NEEDS_REVIEW = "finding_needs_review"

    # Progress
    PROGRESS = "progress"

    # LLM calls
    LLM_CALL_START = "llm_call_start"
    LLM_CALL_COMPLETE = "llm_call_complete"

    # Error/Warning
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class BaseEvent:
    """Base class for all events.

    Attributes:
        type: Event type identifier
        timestamp: ISO8601 timestamp when event occurred
        scan_id: Optional scan identifier
    """

    type: EventType
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
    scan_id: Optional[str] = None

    def to_json_line(self) -> str:
        """Convert event to JSONL line.

        Returns:
            JSON string without newlines
        """
        import json
        return json.dumps(asdict(self), ensure_ascii=False)


# Scan lifecycle events


@dataclass
class ScanStartEvent(BaseEvent):
    """Event emitted when a scan starts."""

    type: EventType = EventType.SCAN_START
    source_path: str = ""
    scan_type: str = "full"  # full/base/incremental
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanCompleteEvent(BaseEvent):
    """Event emitted when a scan completes successfully."""

    type: EventType = EventType.SCAN_COMPLETE
    duration_seconds: float = 0.0
    findings_total: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    tokens_used: int = 0
    result_path: str = ""


@dataclass
class ScanFailedEvent(BaseEvent):
    """Event emitted when a scan fails."""

    type: EventType = EventType.SCAN_FAILED
    error_message: str = ""
    error_type: str = ""
    phase: str = ""


# Phase events


@dataclass
class PhaseStartEvent(BaseEvent):
    """Event emitted when a phase starts."""

    type: EventType = EventType.PHASE_START
    phase: str = ""  # L1_preparation, L1_attack_surface, etc.
    description: str = ""


@dataclass
class PhaseCompleteEvent(BaseEvent):
    """Event emitted when a phase completes."""

    type: EventType = EventType.PHASE_COMPLETE
    phase: str = ""
    duration_seconds: float = 0.0
    findings: int = 0
    tokens_used: int = 0
    output_path: str = ""


@dataclass
class PhaseFailedEvent(BaseEvent):
    """Event emitted when a phase fails."""

    type: EventType = EventType.PHASE_FAILED
    phase: str = ""
    error_message: str = ""


# Engine events


@dataclass
class EngineStartEvent(BaseEvent):
    """Event emitted when an engine starts."""

    type: EventType = EventType.ENGINE_START
    engine: str = ""  # semgrep/codeql/agent/ast_engine
    phase: str = ""


@dataclass
class EngineCompleteEvent(BaseEvent):
    """Event emitted when an engine completes."""

    type: EventType = EventType.ENGINE_COMPLETE
    engine: str = ""
    phase: str = ""
    duration_seconds: float = 0.0
    findings: int = 0
    tokens_used: int = 0


# File processing events


@dataclass
class FileStartEvent(BaseEvent):
    """Event emitted when file processing starts."""

    type: EventType = EventType.FILE_START
    file: str = ""
    index: int = 0
    total: int = 0
    language: str = ""
    size_bytes: int = 0


@dataclass
class FileCompleteEvent(BaseEvent):
    """Event emitted when file processing completes."""

    type: EventType = EventType.FILE_COMPLETE
    file: str = ""
    index: int = 0
    total: int = 0
    findings: int = 0
    tokens_used: int = 0


# Agent events


@dataclass
class AgentThinkingEvent(BaseEvent):
    """Event emitted when Agent is thinking/reasoning."""

    type: EventType = EventType.AGENT_THINKING
    phase: str = ""
    file: str = ""
    turn: int = 0
    role: str = ""  # user/assistant/system/critic/verifier
    message: str = ""
    reasoning: str = ""
    tokens: int = 0


@dataclass
class AgentActionEvent(BaseEvent):
    """Event emitted when Agent performs an action."""

    type: EventType = EventType.AGENT_ACTION
    phase: str = ""
    action: str = ""  # tool call, analysis, etc.
    tool_name: str = ""
    tool_input: dict[str, Any] = field(default_factory=dict)
    file: str = ""


# Adversarial events


@dataclass
class AdversarialStartEvent(BaseEvent):
    """Event emitted when adversarial verification starts."""

    type: EventType = EventType.ADVERSARIAL_START
    finding_id: str = ""
    finding_title: str = ""
    max_rounds: int = 5


@dataclass
class AdversarialRoundEvent(BaseEvent):
    """Event emitted for each adversarial round."""

    type: EventType = EventType.ADVERSARIAL_ROUND
    finding_id: str = ""
    round: int = 0
    role: str = ""  # attacker/defender/verifier
    message: str = ""
    verdict: str = ""  # CONFIRMED/REJECTED/NEEDS_REVIEW
    tokens: int = 0


# Finding events


@dataclass
class FindingNewEvent(BaseEvent):
    """Event emitted when a new finding is discovered."""

    type: EventType = EventType.FINDING_NEW
    finding_id: str = field(default_factory=lambda: str(uuid4()))
    file: str = ""
    line: int = 0
    severity: str = ""  # critical/high/medium/low/info
    vuln_type: str = ""
    title: str = ""
    engine: str = ""
    confidence: float = 0.0


@dataclass
class FindingVerifiedEvent(BaseEvent):
    """Event emitted when a finding is verified."""

    type: EventType = EventType.FINDING_VERIFIED
    finding_id: str = ""
    verdict: str = ""  # CONFIRMED/REJECTED/NEEDS_REVIEW
    exploitability: str = ""  # exploitable/not_exploitable/unknown
    confidence: float = 0.0
    reasoning: str = ""


# Progress events


@dataclass
class ProgressEvent(BaseEvent):
    """Generic progress event."""

    type: EventType = EventType.PROGRESS
    phase: str = ""
    current_step: str = ""
    progress_percent: int = 0
    message: str = ""


# LLM events


@dataclass
class LLMCallStartEvent(BaseEvent):
    """Event emitted when an LLM call starts."""

    type: EventType = EventType.LLM_CALL_START
    phase: str = ""
    model: str = ""
    prompt_tokens: int = 0


@dataclass
class LLMCallCompleteEvent(BaseEvent):
    """Event emitted when an LLM call completes."""

    type: EventType = EventType.LLM_CALL_COMPLETE
    phase: str = ""
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    duration_seconds: float = 0.0


# Error/Warning events


@dataclass
class ErrorEvent(BaseEvent):
    """Event emitted for errors."""

    type: EventType = EventType.ERROR
    phase: str = ""
    file: str = ""
    error_type: str = ""
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class WarningEvent(BaseEvent):
    """Event emitted for warnings."""

    type: EventType = EventType.WARNING
    phase: str = ""
    file: str = ""
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class InfoEvent(BaseEvent):
    """Event emitted for informational messages."""

    type: EventType = EventType.INFO
    phase: str = ""
    message: str = ""
    details: dict[str, Any] = field(default_factory=dict)


# Factory function


def create_event(event_type: EventType, **kwargs) -> BaseEvent:
    """Create an event instance based on type.

    Args:
        event_type: Type of event to create
        **kwargs: Event-specific fields

    Returns:
        Event instance

    Raises:
        ValueError: If event type is unknown
    """
    event_classes = {
        EventType.SCAN_START: ScanStartEvent,
        EventType.SCAN_COMPLETE: ScanCompleteEvent,
        EventType.SCAN_FAILED: ScanFailedEvent,
        EventType.PHASE_START: PhaseStartEvent,
        EventType.PHASE_COMPLETE: PhaseCompleteEvent,
        EventType.PHASE_FAILED: PhaseFailedEvent,
        EventType.ENGINE_START: EngineStartEvent,
        EventType.ENGINE_COMPLETE: EngineCompleteEvent,
        EventType.FILE_START: FileStartEvent,
        EventType.FILE_COMPLETE: FileCompleteEvent,
        EventType.AGENT_THINKING: AgentThinkingEvent,
        EventType.AGENT_ACTION: AgentActionEvent,
        EventType.ADVERSARIAL_START: AdversarialStartEvent,
        EventType.ADVERSARIAL_ROUND: AdversarialRoundEvent,
        EventType.FINDING_NEW: FindingNewEvent,
        EventType.FINDING_VERIFIED: FindingVerifiedEvent,
        EventType.PROGRESS: ProgressEvent,
        EventType.LLM_CALL_START: LLMCallStartEvent,
        EventType.LLM_CALL_COMPLETE: LLMCallCompleteEvent,
        EventType.ERROR: ErrorEvent,
        EventType.WARNING: WarningEvent,
        EventType.INFO: InfoEvent,
    }

    event_class = event_classes.get(event_type)
    if event_class is None:
        raise ValueError(f"Unknown event type: {event_type}")

    return event_class(type=event_type, **kwargs)
