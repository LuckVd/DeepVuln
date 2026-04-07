"""Event emitter for JSONL output format.

This module provides the EventEmitter class that handles emitting
events in JSONL format to stdout or a file.
"""

import sys
from pathlib import Path
from typing import TextIO, Optional

from src.cli.output.events import BaseEvent, EventType


class EventEmitter:
    """Emitter for structured events in JSONL format.

    This class handles emitting events as JSONL (JSON Lines) where each
    line is a valid JSON object. Events can be written to stdout or a file.

    Example:
        emitter = EventEmitter(output_format="jsonl")
        emitter.emit(EventType.SCAN_START, source_path="/src")
        emitter.emit(EventType.PHASE_START, phase="L1_preparation")
    """

    def __init__(
        self,
        output_format: str = "text",
        output_file: Optional[Path] = None,
    ):
        """Initialize the event emitter.

        Args:
            output_format: Output format ("jsonl" or "text")
            output_file: Optional file path to write events to.
                        If None, writes to stdout.
        """
        self.output_format = output_format
        self.output_file = output_file
        self._file_handle: Optional[TextIO] = None

        if output_file and output_format == "jsonl":
            # Ensure parent directory exists
            output_file.parent.mkdir(parents=True, exist_ok=True)
            self._file_handle = open(output_file, "w", encoding="utf-8")

    def emit(self, event_type: EventType, **kwargs) -> Optional[str]:
        """Emit an event.

        Args:
            event_type: Type of event to emit
            **kwargs: Event-specific fields

        Returns:
            JSONL line if output_format is jsonl, None otherwise
        """
        if self.output_format != "jsonl":
            return None

        from src.cli.output.events import create_event

        event = create_event(event_type, **kwargs)
        json_line = event.to_json_line()

        if self._file_handle:
            self._file_handle.write(json_line + "\n")
            self._file_handle.flush()
        else:
            # Write to stdout
            print(json_line, flush=True)

        return json_line

    def emit_scan_start(self, source_path: str, scan_type: str = "full", config: dict = None) -> Optional[str]:
        """Emit scan start event.

        Args:
            source_path: Path to source code being scanned
            scan_type: Type of scan (full/base/incremental)
            config: Scan configuration

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.SCAN_START,
            source_path=source_path,
            scan_type=scan_type,
            config=config or {},
        )

    def emit_phase_start(self, phase: str, description: str = "") -> Optional[str]:
        """Emit phase start event.

        Args:
            phase: Phase name (e.g., "L1_preparation")
            description: Phase description

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.PHASE_START,
            phase=phase,
            description=description,
        )

    def emit_phase_complete(
        self,
        phase: str,
        duration_seconds: float = 0.0,
        findings: int = 0,
        tokens_used: int = 0,
        output_path: str = "",
    ) -> Optional[str]:
        """Emit phase complete event.

        Args:
            phase: Phase name
            duration_seconds: Phase duration in seconds
            findings: Number of findings found
            tokens_used: LLM tokens consumed
            output_path: Path to phase output file

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.PHASE_COMPLETE,
            phase=phase,
            duration_seconds=duration_seconds,
            findings=findings,
            tokens_used=tokens_used,
            output_path=output_path,
        )

    def emit_phase_failed(self, phase: str, error_message: str) -> Optional[str]:
        """Emit phase failed event.

        Args:
            phase: Phase name
            error_message: Error message

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.PHASE_FAILED,
            phase=phase,
            error_message=error_message,
        )

    def emit_engine_start(self, engine: str, phase: str = "") -> Optional[str]:
        """Emit engine start event.

        Args:
            engine: Engine name (semgrep/codeql/agent/ast_engine)
            phase: Current phase

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.ENGINE_START,
            engine=engine,
            phase=phase,
        )

    def emit_engine_complete(
        self,
        engine: str,
        phase: str = "",
        duration_seconds: float = 0.0,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> Optional[str]:
        """Emit engine complete event.

        Args:
            engine: Engine name
            phase: Current phase
            duration_seconds: Duration in seconds
            findings: Findings found
            tokens_used: LLM tokens consumed

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.ENGINE_COMPLETE,
            engine=engine,
            phase=phase,
            duration_seconds=duration_seconds,
            findings=findings,
            tokens_used=tokens_used,
        )

    def emit_file_start(
        self,
        file: str,
        index: int = 0,
        total: int = 0,
        language: str = "",
        size_bytes: int = 0,
    ) -> Optional[str]:
        """Emit file processing start event.

        Args:
            file: File path
            index: File index (1-based)
            total: Total number of files
            language: Programming language
            size_bytes: File size in bytes

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.FILE_START,
            file=file,
            index=index,
            total=total,
            language=language,
            size_bytes=size_bytes,
        )

    def emit_file_complete(
        self,
        file: str,
        index: int = 0,
        total: int = 0,
        findings: int = 0,
        tokens_used: int = 0,
    ) -> Optional[str]:
        """Emit file processing complete event.

        Args:
            file: File path
            index: File index
            total: Total files
            findings: Findings found in file
            tokens_used: LLM tokens consumed

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.FILE_COMPLETE,
            file=file,
            index=index,
            total=total,
            findings=findings,
            tokens_used=tokens_used,
        )

    def emit_agent_thinking(
        self,
        phase: str,
        turn: int,
        role: str,
        message: str,
        reasoning: str = "",
        file: str = "",
        tokens: int = 0,
    ) -> Optional[str]:
        """Emit Agent thinking event.

        Args:
            phase: Current phase
            turn: Turn number
            role: Agent role (user/assistant/system/critic/verifier)
            message: Agent message
            reasoning: Agent reasoning (if available)
            file: Current file being analyzed
            tokens: Tokens consumed

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.AGENT_THINKING,
            phase=phase,
            turn=turn,
            role=role,
            message=message,
            reasoning=reasoning,
            file=file,
            tokens=tokens,
        )

    def emit_adversarial_start(
        self,
        finding_id: str,
        finding_title: str,
        max_rounds: int = 5,
    ) -> Optional[str]:
        """Emit adversarial verification start event.

        Args:
            finding_id: Finding ID
            finding_title: Finding title
            max_rounds: Maximum debate rounds

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.ADVERSARIAL_START,
            finding_id=finding_id,
            finding_title=finding_title,
            max_rounds=max_rounds,
        )

    def emit_adversarial_round(
        self,
        finding_id: str,
        round: int,
        role: str,
        message: str,
        verdict: str = "",
        tokens: int = 0,
    ) -> Optional[str]:
        """Emit adversarial round event.

        Args:
            finding_id: Finding ID
            round: Round number
            role: Role (attacker/defender/verifier)
            message: Message content
            verdict: Verdict (if available)
            tokens: Tokens consumed

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.ADVERSARIAL_ROUND,
            finding_id=finding_id,
            round=round,
            role=role,
            message=message,
            verdict=verdict,
            tokens=tokens,
        )

    def emit_finding_new(
        self,
        file: str,
        line: int,
        severity: str,
        vuln_type: str,
        title: str,
        engine: str,
        confidence: float = 0.0,
    ) -> Optional[str]:
        """Emit new finding event.

        Args:
            file: File path
            line: Line number
            severity: Severity level
            vuln_type: Vulnerability type
            title: Finding title
            engine: Engine that found it
            confidence: Confidence score

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.FINDING_NEW,
            file=file,
            line=line,
            severity=severity,
            vuln_type=vuln_type,
            title=title,
            engine=engine,
            confidence=confidence,
        )

    def emit_finding_verified(
        self,
        finding_id: str,
        verdict: str,
        exploitability: str = "",
        confidence: float = 0.0,
        reasoning: str = "",
    ) -> Optional[str]:
        """Emit finding verified event.

        Args:
            finding_id: Finding ID
            verdict: Verdict (CONFIRMED/REJECTED/NEEDS_REVIEW)
            exploitability: Exploitability status
            confidence: Confidence score
            reasoning: Reasoning

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.FINDING_VERIFIED,
            finding_id=finding_id,
            verdict=verdict,
            exploitability=exploitability,
            confidence=confidence,
            reasoning=reasoning,
        )

    def emit_scan_complete(
        self,
        duration_seconds: float = 0.0,
        findings_total: int = 0,
        findings_by_severity: dict = None,
        tokens_used: int = 0,
        result_path: str = "",
    ) -> Optional[str]:
        """Emit scan complete event.

        Args:
            duration_seconds: Total scan duration
            findings_total: Total findings
            findings_by_severity: Findings by severity level
            tokens_used: Total tokens consumed
            result_path: Path to result file

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.SCAN_COMPLETE,
            duration_seconds=duration_seconds,
            findings_total=findings_total,
            findings_by_severity=findings_by_severity or {},
            tokens_used=tokens_used,
            result_path=result_path,
        )

    def emit_scan_failed(
        self,
        error_message: str,
        error_type: str = "",
        phase: str = "",
    ) -> Optional[str]:
        """Emit scan failed event.

        Args:
            error_message: Error message
            error_type: Error type
            phase: Phase where failure occurred

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.SCAN_FAILED,
            error_message=error_message,
            error_type=error_type,
            phase=phase,
        )

    def emit_progress(
        self,
        phase: str,
        current_step: str,
        progress_percent: int = 0,
        message: str = "",
    ) -> Optional[str]:
        """Emit progress event.

        Args:
            phase: Current phase
            current_step: Current step description
            progress_percent: Progress percentage (0-100)
            message: Additional message

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.PROGRESS,
            phase=phase,
            current_step=current_step,
            progress_percent=progress_percent,
            message=message,
        )

    def emit_error(
        self,
        phase: str,
        message: str,
        file: str = "",
        error_type: str = "",
        details: dict = None,
    ) -> Optional[str]:
        """Emit error event.

        Args:
            phase: Current phase
            message: Error message
            file: File where error occurred
            error_type: Error type
            details: Additional details

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.ERROR,
            phase=phase,
            message=message,
            file=file,
            error_type=error_type,
            details=details or {},
        )

    def emit_warning(
        self,
        phase: str,
        message: str,
        file: str = "",
        details: dict = None,
    ) -> Optional[str]:
        """Emit warning event.

        Args:
            phase: Current phase
            message: Warning message
            file: Related file
            details: Additional details

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.WARNING,
            phase=phase,
            message=message,
            file=file,
            details=details or {},
        )

    def emit_info(
        self,
        phase: str,
        message: str,
        details: dict = None,
    ) -> Optional[str]:
        """Emit info event.

        Args:
            phase: Current phase
            message: Info message
            details: Additional details

        Returns:
            JSONL line if jsonl format
        """
        return self.emit(
            EventType.INFO,
            phase=phase,
            message=message,
            details=details or {},
        )

    def close(self):
        """Close the file handle if open."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
