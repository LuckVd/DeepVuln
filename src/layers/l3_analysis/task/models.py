"""
Task Models

Data models for Agent task management, including task definition,
context, and results.
"""

from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class TaskType(str, Enum):
    """Types of audit tasks."""

    ENTRY_POINT_ANALYSIS = "entry_point_analysis"  # Analyze an entry point for vulnerabilities
    DATAFLOW_TRACE = "dataflow_trace"  # Trace data flow from source to sink
    AUTH_CHECK = "auth_check"  # Check authentication/authorization
    CRYPTO_AUDIT = "crypto_audit"  # Audit cryptographic operations
    CONFIG_REVIEW = "config_review"  # Review configuration files
    FILE_SCAN = "file_scan"  # General file security scan
    FUNCTION_ANALYSIS = "function_analysis"  # Analyze a specific function
    API_SECURITY = "api_security"  # API endpoint security analysis
    DEPENDENCY_CHECK = "dependency_check"  # Check for vulnerable dependencies


class TaskPriority(str, Enum):
    """Priority levels for tasks."""

    CRITICAL = "critical"  # Must complete immediately
    HIGH = "high"  # High priority
    MEDIUM = "medium"  # Normal priority
    LOW = "low"  # Low priority, can be deferred


class TaskStatus(str, Enum):
    """Status of a task."""

    PENDING = "pending"  # Task is waiting to be executed
    QUEUED = "queued"  # Task is in the execution queue
    RUNNING = "running"  # Task is currently being executed
    COMPLETED = "completed"  # Task completed successfully
    FAILED = "failed"  # Task execution failed
    TIMEOUT = "timeout"  # Task timed out
    CANCELLED = "cancelled"  # Task was cancelled
    SKIPPED = "skipped"  # Task was skipped (e.g., duplicate)


class TaskContext(BaseModel):
    """
    Code context for an audit task.

    Contains all the information needed for the Agent to understand
    and analyze the target code.
    """

    # Source code
    code_snippet: str = Field(..., description="The main code to analyze")
    language: str = Field(..., description="Programming language")
    file_path: str = Field(..., description="File path relative to project root")

    # Location
    line_start: int | None = Field(default=None, ge=1, description="Start line of code snippet")
    line_end: int | None = Field(default=None, ge=1, description="End line of code snippet")
    function_name: str | None = Field(default=None, description="Function/method name")

    # Additional context
    imports: list[str] = Field(
        default_factory=list,
        description="Import statements for context",
    )
    related_functions: list[str] = Field(
        default_factory=list,
        description="Names of related functions to include",
    )
    related_code: list[str] = Field(
        default_factory=list,
        description="Additional code snippets for context",
    )

    # Entry point context (if applicable)
    entry_point_type: str | None = Field(
        default=None,
        description="Type of entry point (http, rpc, etc.)",
    )
    http_method: str | None = Field(default=None, description="HTTP method if applicable")
    endpoint_path: str | None = Field(default=None, description="Endpoint path if applicable")
    parameters: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Parameter information",
    )

    # Security context
    auth_required: bool = Field(
        default=False,
        description="Whether authentication is required",
    )
    data_sensitivity: str | None = Field(
        default=None,
        description="Data sensitivity level (high, medium, low)",
    )

    # Metadata
    framework: str | None = Field(default=None, description="Framework name")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    @property
    def code_length(self) -> int:
        """Get the length of the code snippet."""
        return len(self.code_snippet)

    @property
    def line_count(self) -> int:
        """Get the number of lines in the code snippet."""
        return len(self.code_snippet.splitlines())

    def to_prompt_context(self) -> str:
        """Generate context string for LLM prompt."""
        parts = [
            f"File: {self.file_path}",
            f"Language: {self.language}",
        ]

        if self.function_name:
            parts.append(f"Function: {self.function_name}")

        if self.entry_point_type:
            parts.append(f"Entry Point Type: {self.entry_point_type}")
            if self.http_method and self.endpoint_path:
                parts.append(f"Endpoint: {self.http_method} {self.endpoint_path}")

        if self.auth_required:
            parts.append("Authentication: Required")
        else:
            parts.append("Authentication: None")

        if self.parameters:
            param_names = [p.get("name", "?") for p in self.parameters]
            parts.append(f"Parameters: {', '.join(param_names)}")

        return "\n".join(parts)


class AgentTask(BaseModel):
    """
    A single audit task for the Agent.

    Represents a unit of work that can be executed by the OpenCode Agent.
    """

    # Identity
    id: str = Field(..., description="Unique task identifier")
    target_id: str | None = Field(
        default=None,
        description="ID of the AuditTarget this task belongs to",
    )

    # Classification
    task_type: TaskType = Field(..., description="Type of audit task")
    priority: TaskPriority = Field(
        default=TaskPriority.MEDIUM,
        description="Task priority level",
    )
    status: TaskStatus = Field(
        default=TaskStatus.PENDING,
        description="Current task status",
    )

    # Context
    context: TaskContext = Field(..., description="Code context for this task")

    # Analysis configuration
    focus_vulnerabilities: list[str] = Field(
        default_factory=list,
        description="Vulnerability types to focus on",
    )
    custom_prompt: str | None = Field(
        default=None,
        description="Custom prompt additions",
    )

    # Execution configuration
    max_tokens: int = Field(
        default=4096,
        ge=256,
        description="Maximum tokens for this task",
    )
    timeout_seconds: int = Field(
        default=120,
        ge=10,
        description="Timeout for task execution",
    )
    retry_count: int = Field(
        default=0,
        ge=0,
        le=3,
        description="Number of retries attempted",
    )
    max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        description="Maximum retry attempts",
    )

    # Dependencies
    depends_on: list[str] = Field(
        default_factory=list,
        description="Task IDs that must complete before this task",
    )

    # Timestamps
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="When the task was created",
    )
    started_at: datetime | None = Field(
        default=None,
        description="When execution started",
    )
    completed_at: datetime | None = Field(
        default=None,
        description="When execution completed",
    )

    # Result (populated after execution)
    result: "TaskResult | None" = Field(
        default=None,
        description="Task execution result",
    )

    # Metadata
    tags: list[str] = Field(
        default_factory=list,
        description="Tags for categorization",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    @property
    def is_ready(self) -> bool:
        """Check if task is ready to be executed."""
        return self.status == TaskStatus.PENDING

    @property
    def is_terminal(self) -> bool:
        """Check if task is in a terminal state."""
        return self.status in (
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.TIMEOUT,
            TaskStatus.CANCELLED,
            TaskStatus.SKIPPED,
        )

    @property
    def can_retry(self) -> bool:
        """Check if task can be retried."""
        return (
            self.status in (TaskStatus.FAILED, TaskStatus.TIMEOUT)
            and self.retry_count < self.max_retries
        )

    @property
    def duration_seconds(self) -> float | None:
        """Get task duration if completed."""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None

    def mark_started(self) -> None:
        """Mark task as started."""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.now(UTC)

    def mark_completed(self, result: "TaskResult") -> None:
        """Mark task as completed with result."""
        self.status = TaskStatus.COMPLETED
        self.completed_at = datetime.now(UTC)
        self.result = result

    def mark_failed(self, error: str) -> None:
        """Mark task as failed with error message."""
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.now(UTC)
        self.result = TaskResult(
            task_id=self.id,
            success=False,
            error_message=error,
        )

    def mark_timeout(self) -> None:
        """Mark task as timed out."""
        self.status = TaskStatus.TIMEOUT
        self.completed_at = datetime.now(UTC)

    def increment_retry(self) -> None:
        """Increment retry count and reset status."""
        self.retry_count += 1
        self.status = TaskStatus.PENDING
        self.started_at = None
        self.completed_at = None


class TaskResult(BaseModel):
    """
    Result of executing an Agent task.

    Contains findings, token usage, and execution metadata.
    """

    # Identity
    task_id: str = Field(..., description="ID of the task this result belongs to")

    # Status
    success: bool = Field(..., description="Whether the task completed successfully")
    error_message: str | None = Field(
        default=None,
        description="Error message if task failed",
    )

    # Findings (simplified for this module, full Finding in models.py)
    findings_raw: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw findings from the Agent",
    )
    findings_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings",
    )

    # Token usage
    prompt_tokens: int = Field(default=0, ge=0, description="Tokens used in prompt")
    completion_tokens: int = Field(default=0, ge=0, description="Tokens in completion")
    total_tokens: int = Field(default=0, ge=0, description="Total tokens used")

    # Timing
    latency_seconds: float = Field(
        default=0.0,
        ge=0.0,
        description="Execution latency",
    )

    # Raw response
    raw_response: str | None = Field(
        default=None,
        description="Raw LLM response",
    )

    # Metadata
    model: str | None = Field(default=None, description="Model used")
    provider: str | None = Field(default=None, description="Provider used")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata",
    )

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Add a finding to the result."""
        self.findings_raw.append(finding)
        self.findings_count = len(self.findings_raw)

    def get_findings_by_severity(self, severity: str) -> list[dict[str, Any]]:
        """Get findings filtered by severity."""
        return [
            f for f in self.findings_raw
            if f.get("severity", "").lower() == severity.lower()
        ]


class TaskBatch(BaseModel):
    """
    A batch of tasks to be executed together.

    Used for aggregating similar tasks to reduce LLM calls.
    """

    # Identity
    id: str = Field(..., description="Unique batch identifier")
    name: str = Field(..., description="Batch name")

    # Tasks
    task_ids: list[str] = Field(
        default_factory=list,
        description="IDs of tasks in this batch",
    )
    tasks: list[AgentTask] = Field(
        default_factory=list,
        description="Tasks in this batch",
    )

    # Configuration
    batch_type: TaskType = Field(..., description="Type of tasks in batch")
    priority: TaskPriority = Field(
        default=TaskPriority.MEDIUM,
        description="Batch priority (highest of tasks)",
    )

    # Execution
    max_tokens: int = Field(
        default=8192,
        ge=512,
        description="Maximum tokens for batch",
    )
    timeout_seconds: int = Field(
        default=300,
        ge=30,
        description="Timeout for batch execution",
    )

    # Status
    status: TaskStatus = Field(
        default=TaskStatus.PENDING,
        description="Batch status",
    )
    result: TaskResult | None = Field(
        default=None,
        description="Combined batch result",
    )

    @property
    def task_count(self) -> int:
        """Number of tasks in the batch."""
        return len(self.task_ids) or len(self.tasks)

    def add_task(self, task: AgentTask) -> None:
        """Add a task to the batch."""
        if task.id not in self.task_ids:
            self.task_ids.append(task.id)
            self.tasks.append(task)

            # Update priority if needed
            priority_order = {
                TaskPriority.CRITICAL: 0,
                TaskPriority.HIGH: 1,
                TaskPriority.MEDIUM: 2,
                TaskPriority.LOW: 3,
            }
            if priority_order.get(task.priority, 3) < priority_order.get(self.priority, 3):
                self.priority = task.priority

    def can_add_task(self, task: AgentTask, max_batch_size: int = 5) -> bool:
        """Check if a task can be added to the batch."""
        if self.task_count >= max_batch_size:
            return False
        if task.task_type != self.batch_type:
            return False
        if task.status != TaskStatus.PENDING:
            return False
        return True

    def get_combined_context(self) -> str:
        """Get combined context string for all tasks in batch."""
        contexts = []
        for i, task in enumerate(self.tasks, 1):
            contexts.append(f"--- Task {i}: {task.context.function_name or task.context.file_path} ---")
            contexts.append(task.context.to_prompt_context())
            contexts.append(task.context.code_snippet)
            contexts.append("")
        return "\n".join(contexts)
