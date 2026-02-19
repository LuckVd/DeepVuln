"""
Task Dispatcher

Dispatches and manages parallel execution of Agent tasks.
"""

import asyncio
from collections import deque
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Awaitable, Callable

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.task.models import (
    AgentTask,
    TaskBatch,
    TaskPriority,
    TaskResult,
    TaskStatus,
    TaskType,
)


class TaskDispatcher:
    """
    Dispatches and manages Agent task execution.

    The dispatcher:
    1. Manages a queue of pending tasks
    2. Executes tasks in parallel with semaphore control
    3. Handles retries for failed tasks
    4. Collects and aggregates results
    """

    # Default configuration
    DEFAULT_MAX_CONCURRENT = 3
    DEFAULT_TIMEOUT = 120
    DEFAULT_MAX_RETRIES = 2

    # Priority weights for scheduling
    PRIORITY_WEIGHTS = {
        TaskPriority.CRITICAL: 0,
        TaskPriority.HIGH: 1,
        TaskPriority.MEDIUM: 2,
        TaskPriority.LOW: 3,
    }

    def __init__(
        self,
        max_concurrent: int = DEFAULT_MAX_CONCURRENT,
        default_timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRIES,
        on_task_complete: Callable[[AgentTask], None] | None = None,
        on_task_failed: Callable[[AgentTask, str], None] | None = None,
    ):
        """
        Initialize the task dispatcher.

        Args:
            max_concurrent: Maximum concurrent tasks.
            default_timeout: Default task timeout in seconds.
            max_retries: Maximum retries for failed tasks.
            on_task_complete: Callback for task completion.
            on_task_failed: Callback for task failure.
        """
        self.logger = get_logger(__name__)
        self.max_concurrent = max_concurrent
        self.default_timeout = default_timeout
        self.max_retries = max_retries
        self.on_task_complete = on_task_complete
        self.on_task_failed = on_task_failed

        # Task queues
        self._pending: deque[AgentTask] = deque()
        self._running: dict[str, AgentTask] = {}
        self._completed: list[AgentTask] = []
        self._failed: list[AgentTask] = []

        # Concurrency control
        self._semaphore: asyncio.Semaphore | None = None
        self._lock = asyncio.Lock()

        # Statistics
        self._stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "retried": 0,
            "total_tokens": 0,
        }

    @property
    def pending_count(self) -> int:
        """Number of pending tasks."""
        return len(self._pending)

    @property
    def running_count(self) -> int:
        """Number of running tasks."""
        return len(self._running)

    @property
    def completed_count(self) -> int:
        """Number of completed tasks."""
        return len(self._completed)

    @property
    def failed_count(self) -> int:
        """Number of failed tasks."""
        return len(self._failed)

    def add_task(self, task: AgentTask) -> None:
        """
        Add a task to the pending queue.

        Args:
            task: Task to add.
        """
        if task.status not in (TaskStatus.PENDING, TaskStatus.QUEUED):
            self.logger.warning(f"Cannot add task {task.id} with status {task.status}")
            return

        task.status = TaskStatus.QUEUED
        self._pending.append(task)
        self._stats["total_tasks"] += 1

    def add_tasks(self, tasks: list[AgentTask]) -> None:
        """
        Add multiple tasks to the queue.

        Args:
            tasks: Tasks to add.
        """
        for task in tasks:
            self.add_task(task)

    def add_batch(self, batch: TaskBatch) -> None:
        """
        Add all tasks from a batch.

        Args:
            batch: Task batch to add.
        """
        for task in batch.tasks:
            self.add_task(task)

    def sort_queue(self) -> None:
        """Sort pending queue by priority."""
        tasks = list(self._pending)
        tasks.sort(key=lambda t: self.PRIORITY_WEIGHTS.get(t.priority, 3))
        self._pending = deque(tasks)

    async def execute_all(
        self,
        executor: Callable[[AgentTask], "Awaitable[TaskResult]"],
        progress_callback: Callable[[int, int], None] | None = None,
    ) -> list[AgentTask]:
        """
        Execute all pending tasks.

        Args:
            executor: Async function to execute a task.
            progress_callback: Callback for progress updates (completed, total).

        Returns:
            List of all processed tasks.
        """
        if not self._pending:
            self.logger.info("No tasks to execute")
            return []

        # Sort by priority
        self.sort_queue()

        # Initialize semaphore
        self._semaphore = asyncio.Semaphore(self.max_concurrent)

        total = len(self._pending)
        self.logger.info(
            f"Starting execution of {total} tasks "
            f"(max concurrent: {self.max_concurrent})"
        )

        # Create tasks for all pending items
        async_tasks = []
        while self._pending:
            task = self._pending.popleft()
            async_task = asyncio.create_task(
                self._execute_with_semaphore(task, executor)
            )
            async_tasks.append(async_task)

            # Progress callback
            if progress_callback:
                progress_callback(self.completed_count + self.failed_count, total)

        # Wait for all tasks to complete
        await asyncio.gather(*async_tasks, return_exceptions=True)

        # Final progress
        if progress_callback:
            progress_callback(total, total)

        self.logger.info(
            f"Execution complete: {self.completed_count} completed, "
            f"{self.failed_count} failed"
        )

        # Return all processed tasks
        return self._completed + self._failed

    async def _execute_with_semaphore(
        self,
        task: AgentTask,
        executor: Callable[[AgentTask], "Awaitable[TaskResult]"],
    ) -> AgentTask:
        """
        Execute a task with semaphore control.

        Args:
            task: Task to execute.
            executor: Async function to execute the task.

        Returns:
            The processed task.
        """
        async with self._semaphore:
            return await self._execute_task(task, executor)

    async def _execute_task(
        self,
        task: AgentTask,
        executor: Callable[[AgentTask], "Awaitable[TaskResult]"],
    ) -> AgentTask:
        """
        Execute a single task with retry logic.

        Args:
            task: Task to execute.
            executor: Async function to execute the task.

        Returns:
            The processed task.
        """
        max_attempts = task.max_retries + 1

        for attempt in range(max_attempts):
            try:
                # Mark as running
                task.mark_started()
                async with self._lock:
                    self._running[task.id] = task

                # Execute with timeout
                timeout = task.timeout_seconds or self.default_timeout
                result = await asyncio.wait_for(
                    executor(task),
                    timeout=timeout,
                )

                # Handle result
                if isinstance(result, TaskResult):
                    task.mark_completed(result)
                    self._update_stats(result)
                else:
                    # If executor returns something else, treat as success
                    task.mark_completed(TaskResult(
                        task_id=task.id,
                        success=True,
                        raw_response=str(result),
                    ))

                # Move to completed
                async with self._lock:
                    if task.id in self._running:
                        del self._running[task.id]
                    self._completed.append(task)
                    self._stats["completed"] += 1

                # Callback
                if self.on_task_complete:
                    self.on_task_complete(task)

                return task

            except asyncio.TimeoutError:
                self.logger.warning(f"Task {task.id} timed out (attempt {attempt + 1})")
                task.mark_timeout()

                if attempt < max_attempts - 1:
                    task.increment_retry()
                    self._stats["retried"] += 1
                    continue

                # Max retries reached
                async with self._lock:
                    if task.id in self._running:
                        del self._running[task.id]
                    self._failed.append(task)
                    self._stats["failed"] += 1

                if self.on_task_failed:
                    self.on_task_failed(task, "timeout")

                return task

            except Exception as e:
                self.logger.error(f"Task {task.id} failed: {e}")
                task.mark_failed(str(e))

                if attempt < max_attempts - 1:
                    task.increment_retry()
                    self._stats["retried"] += 1
                    continue

                # Max retries reached
                async with self._lock:
                    if task.id in self._running:
                        del self._running[task.id]
                    self._failed.append(task)
                    self._stats["failed"] += 1

                if self.on_task_failed:
                    self.on_task_failed(task, str(e))

                return task

        return task

    def _update_stats(self, result: TaskResult) -> None:
        """Update statistics with result data."""
        self._stats["total_tokens"] += result.total_tokens

    def get_results(self) -> list[TaskResult]:
        """
        Get all task results.

        Returns:
            List of task results.
        """
        return [
            task.result for task in self._completed
            if task.result is not None
        ]

    def get_findings(self) -> list[dict[str, Any]]:
        """
        Get all findings from completed tasks.

        Returns:
            List of all findings.
        """
        findings = []
        for task in self._completed:
            if task.result:
                findings.extend(task.result.findings_raw)
        return findings

    def get_statistics(self) -> dict[str, Any]:
        """
        Get execution statistics.

        Returns:
            Statistics dictionary.
        """
        return {
            **self._stats,
            "pending": self.pending_count,
            "running": self.running_count,
            "completed": self.completed_count,
            "failed": self.failed_count,
            "success_rate": (
                self.completed_count / self._stats["total_tasks"]
                if self._stats["total_tasks"] > 0
                else 0
            ),
        }

    def reset(self) -> None:
        """Reset the dispatcher state."""
        self._pending.clear()
        self._running.clear()
        self._completed.clear()
        self._failed.clear()
        self._stats = {
            "total_tasks": 0,
            "completed": 0,
            "failed": 0,
            "retried": 0,
            "total_tokens": 0,
        }

    async def execute_batch(
        self,
        batch: TaskBatch,
        executor: Callable[[TaskBatch], "Awaitable[TaskResult]"],
    ) -> TaskResult:
        """
        Execute a batch of tasks as a single unit.

        Args:
            batch: Task batch to execute.
            executor: Async function to execute the batch.

        Returns:
            Batch execution result.
        """
        batch.status = TaskStatus.RUNNING
        start_time = datetime.now(UTC)

        try:
            timeout = batch.timeout_seconds or self.default_timeout
            result = await asyncio.wait_for(
                executor(batch),
                timeout=timeout,
            )

            batch.status = TaskStatus.COMPLETED
            if isinstance(result, TaskResult):
                batch.result = result

        except asyncio.TimeoutError:
            batch.status = TaskStatus.TIMEOUT
            batch.result = TaskResult(
                task_id=batch.id,
                success=False,
                error_message="Batch execution timed out",
            )

        except Exception as e:
            batch.status = TaskStatus.FAILED
            batch.result = TaskResult(
                task_id=batch.id,
                success=False,
                error_message=str(e),
            )

        return batch.result or TaskResult(
            task_id=batch.id,
            success=batch.status == TaskStatus.COMPLETED,
        )

    def get_task_by_id(self, task_id: str) -> AgentTask | None:
        """
        Get a task by ID.

        Args:
            task_id: Task ID to find.

        Returns:
            Task if found, None otherwise.
        """
        # Check running
        if task_id in self._running:
            return self._running[task_id]

        # Check completed
        for task in self._completed:
            if task.id == task_id:
                return task

        # Check failed
        for task in self._failed:
            if task.id == task_id:
                return task

        # Check pending
        for task in self._pending:
            if task.id == task_id:
                return task

        return None

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a pending task.

        Args:
            task_id: Task ID to cancel.

        Returns:
            True if task was cancelled.
        """
        for task in list(self._pending):
            if task.id == task_id:
                task.status = TaskStatus.CANCELLED
                self._pending.remove(task)
                self.logger.info(f"Cancelled task {task_id}")
                return True

        self.logger.warning(f"Cannot cancel task {task_id}: not in pending queue")
        return False
