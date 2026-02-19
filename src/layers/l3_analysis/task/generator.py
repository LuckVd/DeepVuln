"""
Task Generator

Generates Agent tasks from audit targets and attack surface data.
"""

import uuid
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.strategy.models import (
    AuditPriorityLevel,
    AuditTarget,
)
from src.layers.l3_analysis.task.models import (
    AgentTask,
    TaskBatch,
    TaskContext,
    TaskPriority,
    TaskStatus,
    TaskType,
)


class TaskGenerator:
    """
    Generates Agent tasks from audit targets.

    The task generator:
    1. Converts AuditTargets to AgentTasks
    2. Determines appropriate task types
    3. Sets priority based on target priority
    4. Groups similar tasks into batches
    """

    # Mapping from audit priority to task priority
    PRIORITY_MAP = {
        AuditPriorityLevel.CRITICAL: TaskPriority.CRITICAL,
        AuditPriorityLevel.HIGH: TaskPriority.HIGH,
        AuditPriorityLevel.MEDIUM: TaskPriority.MEDIUM,
        AuditPriorityLevel.LOW: TaskPriority.LOW,
        AuditPriorityLevel.SKIP: TaskPriority.LOW,
    }

    # Task type determination based on target characteristics
    ENTRY_POINT_TASK_TYPES = {
        "http": TaskType.ENTRY_POINT_ANALYSIS,
        "rpc": TaskType.ENTRY_POINT_ANALYSIS,
        "grpc": TaskType.ENTRY_POINT_ANALYSIS,
        "mq": TaskType.ENTRY_POINT_ANALYSIS,
        "websocket": TaskType.ENTRY_POINT_ANALYSIS,
        "cli": TaskType.ENTRY_POINT_ANALYSIS,
        "cron": TaskType.ENTRY_POINT_ANALYSIS,
        "file": TaskType.FILE_SCAN,
    }

    # Default vulnerabilities to focus on by task type
    DEFAULT_FOCUS_VULNERABILITIES = {
        TaskType.ENTRY_POINT_ANALYSIS: [
            "sql_injection",
            "xss",
            "command_injection",
            "auth_bypass",
            "idor",
        ],
        TaskType.DATAFLOW_TRACE: [
            "sql_injection",
            "xss",
            "command_injection",
            "path_traversal",
            "ssrf",
        ],
        TaskType.AUTH_CHECK: [
            "auth_bypass",
            "idor",
            "session_fixation",
        ],
        TaskType.CRYPTO_AUDIT: [
            "crypto_weakness",
            "hardcoded_secrets",
        ],
        TaskType.CONFIG_REVIEW: [
            "hardcoded_secrets",
            "misconfiguration",
        ],
        TaskType.FILE_SCAN: [
            "hardcoded_secrets",
            "sql_injection",
            "xss",
        ],
        TaskType.FUNCTION_ANALYSIS: [
            "sql_injection",
            "command_injection",
            "path_traversal",
        ],
        TaskType.API_SECURITY: [
            "sql_injection",
            "xss",
            "auth_bypass",
            "idor",
            "ssrf",
        ],
        TaskType.DEPENDENCY_CHECK: [
            "vulnerable_dependency",
        ],
    }

    # Default token limits by task type
    DEFAULT_TOKEN_LIMITS = {
        TaskType.ENTRY_POINT_ANALYSIS: 4096,
        TaskType.DATAFLOW_TRACE: 6144,
        TaskType.AUTH_CHECK: 3072,
        TaskType.CRYPTO_AUDIT: 3072,
        TaskType.CONFIG_REVIEW: 2048,
        TaskType.FILE_SCAN: 4096,
        TaskType.FUNCTION_ANALYSIS: 3072,
        TaskType.API_SECURITY: 4096,
        TaskType.DEPENDENCY_CHECK: 2048,
    }

    # Default timeouts by task type (seconds)
    DEFAULT_TIMEOUTS = {
        TaskType.ENTRY_POINT_ANALYSIS: 120,
        TaskType.DATAFLOW_TRACE: 180,
        TaskType.AUTH_CHECK: 90,
        TaskType.CRYPTO_AUDIT: 90,
        TaskType.CONFIG_REVIEW: 60,
        TaskType.FILE_SCAN: 120,
        TaskType.FUNCTION_ANALYSIS: 90,
        TaskType.API_SECURITY: 120,
        TaskType.DEPENDENCY_CHECK: 60,
    }

    def __init__(
        self,
        custom_focus: dict[TaskType, list[str]] | None = None,
        custom_tokens: dict[TaskType, int] | None = None,
        custom_timeouts: dict[TaskType, int] | None = None,
    ):
        """
        Initialize the task generator.

        Args:
            custom_focus: Custom vulnerability focus by task type.
            custom_tokens: Custom token limits by task type.
            custom_timeouts: Custom timeouts by task type.
        """
        self.logger = get_logger(__name__)
        self.focus_vulnerabilities = {
            **self.DEFAULT_FOCUS_VULNERABILITIES,
            **(custom_focus or {}),
        }
        self.token_limits = {
            **self.DEFAULT_TOKEN_LIMITS,
            **(custom_tokens or {}),
        }
        self.timeouts = {
            **self.DEFAULT_TIMEOUTS,
            **(custom_timeouts or {}),
        }

    def generate_tasks(
        self,
        targets: list[AuditTarget],
        source_path: Path | None = None,
    ) -> list[AgentTask]:
        """
        Generate tasks from a list of audit targets.

        Args:
            targets: List of audit targets.
            source_path: Source path for context building.

        Returns:
            List of generated Agent tasks.
        """
        tasks = []

        for target in targets:
            # Skip targets that should be skipped
            if target.priority and target.priority.level == AuditPriorityLevel.SKIP:
                continue

            # Generate task(s) for this target
            target_tasks = self._generate_tasks_for_target(target, source_path)
            tasks.extend(target_tasks)

        self.logger.info(f"Generated {len(tasks)} tasks from {len(targets)} targets")
        return tasks

    def _generate_tasks_for_target(
        self,
        target: AuditTarget,
        source_path: Path | None = None,
    ) -> list[AgentTask]:
        """
        Generate tasks for a single target.

        Args:
            target: The audit target.
            source_path: Source path for context building.

        Returns:
            List of tasks for this target.
        """
        tasks = []

        # Determine task type
        task_type = self._determine_task_type(target)

        # Determine priority
        priority = self._determine_priority(target)

        # Build task context
        context = self._build_context(target, source_path)

        # Create the main task
        task = AgentTask(
            id=self._generate_task_id(),
            target_id=target.id,
            task_type=task_type,
            priority=priority,
            context=context,
            focus_vulnerabilities=self.focus_vulnerabilities.get(task_type, []),
            max_tokens=self.token_limits.get(task_type, 4096),
            timeout_seconds=self.timeouts.get(task_type, 120),
            tags=target.tags,
            metadata={
                "target_name": target.name,
                "target_type": target.target_type,
            },
        )
        tasks.append(task)

        # Generate additional tasks based on target characteristics
        additional_tasks = self._generate_additional_tasks(target, source_path)
        tasks.extend(additional_tasks)

        return tasks

    def _determine_task_type(self, target: AuditTarget) -> TaskType:
        """Determine the appropriate task type for a target."""
        # Entry point type tasks
        if target.entry_point_type:
            return self.ENTRY_POINT_TASK_TYPES.get(
                target.entry_point_type.lower(),
                TaskType.ENTRY_POINT_ANALYSIS,
            )

        # File-based tasks
        if target.target_type == "file":
            file_lower = target.file_path.lower()

            # Check for specific file types
            if any(p in file_lower for p in ["auth", "login", "password", "token"]):
                return TaskType.AUTH_CHECK
            if any(p in file_lower for p in ["crypto", "encrypt", "cipher", "key"]):
                return TaskType.CRYPTO_AUDIT
            if any(p in file_lower for p in ["config", "settings", "env"]):
                return TaskType.CONFIG_REVIEW
            if any(p in file_lower for p in ["api", "route", "controller", "handler"]):
                return TaskType.API_SECURITY

            return TaskType.FILE_SCAN

        # Function-based tasks
        if target.target_type == "function":
            return TaskType.FUNCTION_ANALYSIS

        # Module-based tasks
        if target.target_type == "module":
            return TaskType.FILE_SCAN

        return TaskType.FILE_SCAN

    def _determine_priority(self, target: AuditTarget) -> TaskPriority:
        """Determine task priority from target priority."""
        if target.priority:
            return self.PRIORITY_MAP.get(
                target.priority.level,
                TaskPriority.MEDIUM,
            )
        return TaskPriority.MEDIUM

    def _build_context(
        self,
        target: AuditTarget,
        source_path: Path | None = None,
    ) -> TaskContext:
        """Build task context from target."""
        context = TaskContext(
            code_snippet="",  # Will be filled by ContextBuilder
            language=target.language or self._detect_language(target.file_path),
            file_path=target.file_path,
            line_start=target.line_start,
            line_end=target.line_end,
            function_name=target.function_name,
            entry_point_type=target.entry_point_type,
            http_method=target.http_method,
            endpoint_path=target.endpoint_path,
            auth_required=target.auth_required,
            framework=target.framework,
            metadata=target.metadata,
        )

        # Add parameters if available
        if target.params:
            context.parameters = [
                {"name": p, "type": "unknown"}
                for p in target.params
            ]

        return context

    def _detect_language(self, file_path: str) -> str:
        """Detect language from file extension."""
        ext_to_lang = {
            ".py": "python",
            ".java": "java",
            ".go": "go",
            ".js": "javascript",
            ".ts": "typescript",
            ".jsx": "javascript",
            ".tsx": "typescript",
            ".php": "php",
            ".rb": "ruby",
            ".cs": "csharp",
            ".kt": "kotlin",
            ".rs": "rust",
        }
        ext = Path(file_path).suffix.lower()
        return ext_to_lang.get(ext, "unknown")

    def _generate_additional_tasks(
        self,
        target: AuditTarget,
        source_path: Path | None = None,
    ) -> list[AgentTask]:
        """Generate additional specialized tasks based on target characteristics."""
        additional = []

        # For unauthenticated entry points, add auth check task
        if target.entry_point_type and not target.auth_required:
            context = self._build_context(target, source_path)
            auth_task = AgentTask(
                id=self._generate_task_id(),
                target_id=target.id,
                task_type=TaskType.AUTH_CHECK,
                priority=self._determine_priority(target),
                context=context,
                focus_vulnerabilities=self.focus_vulnerabilities.get(TaskType.AUTH_CHECK, []),
                max_tokens=self.token_limits.get(TaskType.AUTH_CHECK, 3072),
                timeout_seconds=self.timeouts.get(TaskType.AUTH_CHECK, 90),
                tags=["auth_check"] + target.tags,
                metadata={"reason": "unauthenticated_entry_point"},
            )
            additional.append(auth_task)

        return additional

    def _generate_task_id(self) -> str:
        """Generate a unique task ID."""
        return f"task-{uuid.uuid4().hex[:8]}"

    def create_batches(
        self,
        tasks: list[AgentTask],
        max_batch_size: int = 5,
        batch_by_type: bool = True,
    ) -> list[TaskBatch]:
        """
        Create task batches from a list of tasks.

        Args:
            tasks: List of tasks to batch.
            max_batch_size: Maximum tasks per batch.
            batch_by_type: Whether to batch by task type.

        Returns:
            List of task batches.
        """
        batches = []

        if batch_by_type:
            # Group by task type
            tasks_by_type: dict[TaskType, list[AgentTask]] = {}
            for task in tasks:
                if task.task_type not in tasks_by_type:
                    tasks_by_type[task.task_type] = []
                tasks_by_type[task.task_type].append(task)

            # Create batches for each type
            for task_type, type_tasks in tasks_by_type.items():
                type_batches = self._create_batches_for_tasks(
                    type_tasks,
                    task_type,
                    max_batch_size,
                )
                batches.extend(type_batches)
        else:
            # Create batches across all tasks
            batches = self._create_batches_for_tasks(
                tasks,
                None,
                max_batch_size,
            )

        self.logger.info(
            f"Created {len(batches)} batches from {len(tasks)} tasks"
        )
        return batches

    def _create_batches_for_tasks(
        self,
        tasks: list[AgentTask],
        task_type: TaskType | None,
        max_batch_size: int,
    ) -> list[TaskBatch]:
        """Create batches from a list of tasks."""
        batches = []

        # Sort by priority
        priority_order = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.MEDIUM: 2,
            TaskPriority.LOW: 3,
        }
        sorted_tasks = sorted(
            tasks,
            key=lambda t: priority_order.get(t.priority, 3),
        )

        current_batch = None

        for task in sorted_tasks:
            if current_batch is None:
                current_batch = TaskBatch(
                    id=f"batch-{uuid.uuid4().hex[:8]}",
                    name=f"Batch-{task_type.value if task_type else 'mixed'}-{len(batches) + 1}",
                    batch_type=task_type or task.task_type,
                    priority=task.priority,
                )

            if current_batch.can_add_task(task, max_batch_size):
                current_batch.add_task(task)
            else:
                # Finalize current batch and start new one
                batches.append(current_batch)
                current_batch = TaskBatch(
                    id=f"batch-{uuid.uuid4().hex[:8]}",
                    name=f"Batch-{task_type.value if task_type else 'mixed'}-{len(batches) + 1}",
                    batch_type=task_type or task.task_type,
                    priority=task.priority,
                )
                current_batch.add_task(task)

        # Don't forget the last batch
        if current_batch and current_batch.task_count > 0:
            batches.append(current_batch)

        return batches

    def optimize_tasks(
        self,
        tasks: list[AgentTask],
        token_budget: int | None = None,
        time_budget: int | None = None,
    ) -> list[AgentTask]:
        """
        Optimize task list based on resource constraints.

        Args:
            tasks: List of tasks to optimize.
            token_budget: Maximum total tokens.
            time_budget: Maximum total time in seconds.

        Returns:
            Optimized list of tasks.
        """
        if not token_budget and not time_budget:
            return tasks

        optimized = []
        total_tokens = 0
        total_time = 0

        # Sort by priority
        priority_order = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.MEDIUM: 2,
            TaskPriority.LOW: 3,
        }
        sorted_tasks = sorted(
            tasks,
            key=lambda t: priority_order.get(t.priority, 3),
        )

        for task in sorted_tasks:
            task_tokens = task.max_tokens
            task_time = task.timeout_seconds

            # Check budgets
            if token_budget and total_tokens + task_tokens > token_budget:
                continue
            if time_budget and total_time + task_time > time_budget:
                continue

            optimized.append(task)
            total_tokens += task_tokens
            total_time += task_time

        skipped = len(tasks) - len(optimized)
        if skipped > 0:
            self.logger.info(
                f"Optimized tasks: {len(optimized)} kept, {skipped} skipped due to budget"
            )

        return optimized
