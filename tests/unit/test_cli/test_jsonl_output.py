"""Unit tests for JSONL output functionality.

P10-07: Tests for EventEmitter and event types.
"""

import json
from pathlib import Path

import pytest

from src.cli.output import (
    EventEmitter,
    EventType,
    ScanStartEvent,
    ScanCompleteEvent,
    PhaseStartEvent,
    PhaseCompleteEvent,
    EngineStartEvent,
    EngineCompleteEvent,
    FileStartEvent,
    FileCompleteEvent,
    FindingNewEvent,
    FindingVerifiedEvent,
    create_event,
)


class TestEventTypes:
    """Test event type definitions."""

    def test_event_type_values(self):
        """Test that EventType enum has all expected values."""
        # Check that key event types exist (allow for additional types)
        required_types = {
            "scan_start",
            "scan_complete",
            "scan_failed",
            "phase_start",
            "phase_complete",
            "phase_failed",
            "engine_start",
            "engine_complete",
            "file_start",
            "file_complete",
            "agent_thinking",
            "adversarial_start",
            "adversarial_round",
            "finding_new",
            "finding_verified",
            "progress",
            "error",
            "warning",
            "info",
        }

        actual_types = {e.value for e in EventType}
        assert required_types.issubset(actual_types)


class TestEventCreation:
    """Test event creation using factory function."""

    def test_create_scan_start_event(self):
        """Test creating a scan start event."""
        event = create_event(
            EventType.SCAN_START,
            source_path="/src",
            scan_type="full",
            config={"key": "value"},
        )

        assert isinstance(event, ScanStartEvent)
        assert event.type == EventType.SCAN_START
        assert event.source_path == "/src"
        assert event.scan_type == "full"
        assert event.config == {"key": "value"}
        assert "timestamp" in event.to_json_line()

    def test_create_phase_start_event(self):
        """Test creating a phase start event."""
        event = create_event(
            EventType.PHASE_START,
            phase="L1_preparation",
            description="Tech Stack Detection",
        )

        assert isinstance(event, PhaseStartEvent)
        assert event.phase == "L1_preparation"
        assert event.description == "Tech Stack Detection"

    def test_create_finding_new_event(self):
        """Test creating a new finding event."""
        event = create_event(
            EventType.FINDING_NEW,
            file="src/main.py",
            line=42,
            severity="high",
            vuln_type="sql_injection",
            title="SQL Injection Vulnerability",
            engine="agent",
            confidence=0.9,
        )

        assert isinstance(event, FindingNewEvent)
        assert event.file == "src/main.py"
        assert event.line == 42
        assert event.severity == "high"
        assert event.vuln_type == "sql_injection"
        assert event.title == "SQL Injection Vulnerability"
        assert event.confidence == 0.9

    def test_invalid_event_type(self):
        """Test that invalid event type raises error."""
        with pytest.raises(ValueError, match="Unknown event type"):
            create_event("INVALID_TYPE", file="test.py")


class TestEventSerialization:
    """Test event serialization to JSONL format."""

    def test_scan_start_event_serialization(self):
        """Test that scan start event serializes correctly."""
        event = ScanStartEvent(
            type=EventType.SCAN_START,
            source_path="/src",
            scan_type="full",
        )

        json_line = event.to_json_line()
        data = json.loads(json_line)

        assert data["type"] == "scan_start"
        assert data["source_path"] == "/src"
        assert data["scan_type"] == "full"
        assert "timestamp" in data
        assert data["scan_id"] is None

    def test_scan_complete_event_serialization(self):
        """Test that scan complete event serializes correctly."""
        event = ScanCompleteEvent(
            type=EventType.SCAN_COMPLETE,
            duration_seconds=120.5,
            findings_total=10,
            findings_by_severity={"critical": 1, "high": 3, "medium": 6},
            tokens_used=5000,
            result_path="/tmp/result.json",
        )

        json_line = event.to_json_line()
        data = json.loads(json_line)

        assert data["type"] == "scan_complete"
        assert data["duration_seconds"] == 120.5
        assert data["findings_total"] == 10
        assert data["findings_by_severity"]["critical"] == 1
        assert data["tokens_used"] == 5000
        assert data["result_path"] == "/tmp/result.json"

    def test_finding_event_serialization(self):
        """Test that finding event includes UUID."""
        event = FindingNewEvent(
            type=EventType.FINDING_NEW,
            file="src/main.py",
            line=42,
            severity="critical",
            vuln_type="command_injection",
            title="Command Injection",
            engine="semgrep",
            confidence=1.0,
        )

        json_line = event.to_json_line()
        data = json.loads(json_line)

        assert data["type"] == "finding_new"
        assert "finding_id" in data
        assert len(data["finding_id"]) == 36  # UUID format


class TestEventEmitter:
    """Test EventEmitter functionality."""

    def test_emitter_initialization(self):
        """Test emitter initialization with different formats."""
        # Text format (default)
        emitter = EventEmitter(output_format="text")
        assert emitter.output_format == "text"
        assert emitter._file_handle is None

        # JSONL format
        emitter = EventEmitter(output_format="jsonl")
        assert emitter.output_format == "jsonl"

    def test_emitter_returns_none_for_text_format(self):
        """Test that emit returns None for text format."""
        emitter = EventEmitter(output_format="text")

        result = emitter.emit_scan_start("/src")
        assert result is None

    def test_emitter_emits_to_stdout(self):
        """Test that emitter writes to stdout for JSONL format."""
        emitter = EventEmitter(output_format="jsonl")
        captured = []

        def capture_print(msg, **kwargs):
            captured.append(msg)

        import builtins
        original_print = builtins.print
        builtins.print = capture_print

        try:
            result = emitter.emit_scan_start("/src", scan_type="full")
        finally:
            builtins.print = original_print

        assert result is not None
        assert len(captured) == 1

        # Verify JSON format
        data = json.loads(captured[0])
        assert data["type"] == "scan_start"
        assert data["source_path"] == "/src"

    def test_emitter_scan_lifecycle(self):
        """Test complete scan lifecycle events."""
        emitter = EventEmitter(output_format="jsonl")
        events = []

        def capture_print(msg, **kwargs):
            events.append(json.loads(msg))

        import builtins
        original_print = builtins.print
        builtins.print = capture_print

        try:
            # Scan start
            emitter.emit_scan_start("/src", scan_type="full")

            # Phase start
            emitter.emit_phase_start("L1_preparation")
            emitter.emit_phase_complete("L1_preparation", findings=0)

            # Engine start
            emitter.emit_engine_start("semgrep", phase="L2")
            emitter.emit_engine_complete("semgrep", findings=5)

            # Finding
            emitter.emit_finding_new(
                file="src/main.py",
                line=42,
                severity="high",
                vuln_type="sql_injection",
                title="SQL Injection",
                engine="semgrep",
            )

            # Scan complete
            emitter.emit_scan_complete(
                duration_seconds=120,
                findings_total=5,
            )
        finally:
            builtins.print = original_print

        # Verify events
        assert len(events) == 7
        assert events[0]["type"] == "scan_start"
        assert events[1]["type"] == "phase_start"
        assert events[2]["type"] == "phase_complete"
        assert events[3]["type"] == "engine_start"
        assert events[4]["type"] == "engine_complete"
        assert events[5]["type"] == "finding_new"
        assert events[6]["type"] == "scan_complete"

    def test_emitter_file_output(self, tmp_path):
        """Test that emitter can write to file."""
        output_file = tmp_path / "output.jsonl"

        emitter = EventEmitter(output_format="jsonl", output_file=output_file)

        # Emit some events
        emitter.emit_scan_start("/src")
        emitter.emit_phase_start("L1_preparation")
        emitter.emit_scan_complete()

        # Close emitter
        emitter.close()

        # Read file and verify
        content = output_file.read_text()
        lines = content.strip().split("\n")

        assert len(lines) == 3
        assert json.loads(lines[0])["type"] == "scan_start"
        assert json.loads(lines[1])["type"] == "phase_start"
        assert json.loads(lines[2])["type"] == "scan_complete"

    def test_emitter_context_manager(self, tmp_path):
        """Test emitter as context manager."""
        output_file = tmp_path / "output.jsonl"

        with EventEmitter(output_format="jsonl", output_file=output_file) as emitter:
            emitter.emit_scan_start("/src")
            emitter.emit_scan_complete()

        # File should be closed and contain events
        content = output_file.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 2


class TestEventEmitterAdversarial:
    """Test adversarial verification events."""

    def test_adversarial_events(self):
        """Test adversarial event emissions."""
        emitter = EventEmitter(output_format="jsonl")
        events = []

        def capture_print(msg, **kwargs):
            events.append(json.loads(msg))

        import builtins
        original_print = builtins.print
        builtins.print = capture_print

        try:
            # Adversarial start
            emitter.emit_adversarial_start(
                finding_id="abc123",
                finding_title="SQL Injection",
                max_rounds=5,
            )

            # Adversarial round
            emitter.emit_adversarial_round(
                finding_id="abc123",
                round=1,
                role="attacker",
                message="This is exploitable!",
                verdict="CONFIRMED",
                tokens=150,
            )
        finally:
            builtins.print = original_print

        assert len(events) == 2
        assert events[0]["type"] == "adversarial_start"
        assert events[1]["type"] == "adversarial_round"
        assert events[1]["verdict"] == "CONFIRMED"


class TestEventEmitterAgent:
    """Test Agent-related events."""

    def test_agent_events(self):
        """Test Agent event emissions."""
        emitter = EventEmitter(output_format="jsonl")
        events = []

        def capture_print(msg, **kwargs):
            events.append(json.loads(msg))

        import builtins
        original_print = builtins.print
        builtins.print = capture_print

        try:
            # Agent thinking
            emitter.emit_agent_thinking(
                phase="L3_agent",
                turn=1,
                role="assistant",
                message="Analyzing code...",
                reasoning="Checking data flow...",
                file="src/main.py",
                tokens=200,
            )

            # Finding verified
            emitter.emit_finding_verified(
                finding_id="abc123",
                verdict="CONFIRMED",
                exploitability="exploitable",
                confidence=0.95,
                reasoning="Confirmed exploitable via user input",
            )
        finally:
            builtins.print = original_print

        assert len(events) == 2
        assert events[0]["type"] == "agent_thinking"
        assert events[0]["tokens"] == 200
        assert events[1]["type"] == "finding_verified"
        assert events[1]["verdict"] == "CONFIRMED"


class TestEventEmitterErrorHandling:
    """Test error and warning events."""

    def test_error_events(self):
        """Test error event emission."""
        emitter = EventEmitter(output_format="jsonl")
        events = []

        def capture_print(msg, **kwargs):
            events.append(json.loads(msg))

        import builtins
        original_print = builtins.print
        builtins.print = capture_print

        try:
            # Error event
            emitter.emit_error(
                phase="L2_codeql",
                message="Build failed",
                file="project/Makefile",
                error_type="BuildError",
                details={"exit_code": 2},
            )

            # Warning event
            emitter.emit_warning(
                phase="L1_preparation",
                message="Large project detected",
                file=".",
                details={"file_count": 10000},
            )

            # Scan failed
            emitter.emit_scan_failed(
                error_message="Out of memory",
                error_type="MemoryError",
                phase="L3_agent",
            )
        finally:
            builtins.print = original_print

        assert len(events) == 3
        assert events[0]["type"] == "error"
        assert events[1]["type"] == "warning"
        assert events[2]["type"] == "scan_failed"
        assert events[0]["details"]["exit_code"] == 2
        assert events[2]["error_type"] == "MemoryError"
