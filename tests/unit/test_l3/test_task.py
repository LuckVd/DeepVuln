"""
Unit tests for Agent Task module.

Tests task models, generator, dispatcher, and context builder.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.layers.l3_analysis.task.models import (
    AgentTask,
    TaskType,
    TaskPriority,
    TaskStatus,
    TaskContext,
    TaskResult,
    TaskBatch,
)
from src.layers.l3_analysis.task.generator import TaskGenerator
from src.layers.l3_analysis.task.dispatcher import TaskDispatcher
from src.layers.l3_analysis.task.context_builder import ContextBuilder
from src.layers.l3_analysis.strategy.models import (
    AuditPriority,
    AuditPriorityLevel,
    AuditTarget,
)


class TestTaskType:
    """Tests for TaskType enum."""

    def test_task_types_exist(self):
        """Test that all expected task types exist."""
        assert TaskType.ENTRY_POINT_ANALYSIS.value == "entry_point_analysis"
        assert TaskType.DATAFLOW_TRACE.value == "dataflow_trace"
        assert TaskType.AUTH_CHECK.value == "auth_check"
        assert TaskType.CRYPTO_AUDIT.value == "crypto_audit"
        assert TaskType.FILE_SCAN.value == "file_scan"


class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_priorities_exist(self):
        """Test that all expected priorities exist."""
        assert TaskPriority.CRITICAL.value == "critical"
        assert TaskPriority.HIGH.value == "high"
        assert TaskPriority.MEDIUM.value == "medium"
        assert TaskPriority.LOW.value == "low"


class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_statuses_exist(self):
        """Test that all expected statuses exist."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.TIMEOUT.value == "timeout"


class TestTaskContext:
    """Tests for TaskContext model."""

    def test_default_init(self):
        """Test default initialization."""
        context = TaskContext(
            code_snippet="def foo(): pass",
            language="python",
            file_path="test.py",
        )
        assert context.language == "python"
        assert context.file_path == "test.py"
        assert context.auth_required is False

    def test_code_length(self):
        """Test code_length property."""
        context = TaskContext(
            code_snippet="print('hello')",
            language="python",
            file_path="test.py",
        )
        assert context.code_length == 14

    def test_line_count(self):
        """Test line_count property."""
        context = TaskContext(
            code_snippet="line1\nline2\nline3",
            language="python",
            file_path="test.py",
        )
        assert context.line_count == 3

    def test_to_prompt_context(self):
        """Test prompt context generation."""
        context = TaskContext(
            code_snippet="def foo(): pass",
            language="python",
            file_path="src/main.py",
            function_name="foo",
            entry_point_type="http",
            http_method="POST",
            endpoint_path="/api/users",
        )
        prompt = context.to_prompt_context()
        assert "src/main.py" in prompt
        assert "python" in prompt
        assert "foo" in prompt
        assert "POST" in prompt
        assert "/api/users" in prompt


class TestAgentTask:
    """Tests for AgentTask model."""

    @pytest.fixture
    def sample_context(self):
        """Create a sample context."""
        return TaskContext(
            code_snippet="def foo(): pass",
            language="python",
            file_path="test.py",
        )

    def test_default_init(self, sample_context):
        """Test default initialization."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        assert task.id == "task-001"
        assert task.status == TaskStatus.PENDING
        assert task.priority == TaskPriority.MEDIUM
        assert task.max_tokens == 4096

    def test_is_ready(self, sample_context):
        """Test is_ready property."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        assert task.is_ready is True

        task.status = TaskStatus.RUNNING
        assert task.is_ready is False

    def test_is_terminal(self, sample_context):
        """Test is_terminal property."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        assert task.is_terminal is False

        task.status = TaskStatus.COMPLETED
        assert task.is_terminal is True

        task.status = TaskStatus.FAILED
        assert task.is_terminal is True

    def test_can_retry(self, sample_context):
        """Test can_retry property."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
            max_retries=2,
        )
        assert task.can_retry is False  # Not failed yet

        task.status = TaskStatus.FAILED
        assert task.can_retry is True

        task.retry_count = 2
        assert task.can_retry is False

    def test_mark_started(self, sample_context):
        """Test mark_started method."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        task.mark_started()
        assert task.status == TaskStatus.RUNNING
        assert task.started_at is not None

    def test_mark_completed(self, sample_context):
        """Test mark_completed method."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        result = TaskResult(task_id="task-001", success=True)
        task.mark_completed(result)
        assert task.status == TaskStatus.COMPLETED
        assert task.result == result
        assert task.completed_at is not None

    def test_mark_failed(self, sample_context):
        """Test mark_failed method."""
        task = AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=sample_context,
        )
        task.mark_failed("Something went wrong")
        assert task.status == TaskStatus.FAILED
        assert task.result is not None
        assert task.result.error_message == "Something went wrong"


class TestTaskResult:
    """Tests for TaskResult model."""

    def test_default_init(self):
        """Test default initialization."""
        result = TaskResult(task_id="task-001", success=True)
        assert result.task_id == "task-001"
        assert result.success is True
        assert result.findings_count == 0

    def test_add_finding(self):
        """Test adding findings."""
        result = TaskResult(task_id="task-001", success=True)
        result.add_finding({"type": "sql_injection", "severity": "high"})
        assert result.findings_count == 1

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        result = TaskResult(task_id="task-001", success=True)
        result.add_finding({"type": "a", "severity": "high"})
        result.add_finding({"type": "b", "severity": "critical"})
        result.add_finding({"type": "c", "severity": "high"})

        high_findings = result.get_findings_by_severity("high")
        assert len(high_findings) == 2


class TestTaskBatch:
    """Tests for TaskBatch model."""

    @pytest.fixture
    def sample_task(self):
        """Create a sample task."""
        return AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=TaskContext(
                code_snippet="def foo(): pass",
                language="python",
                file_path="test.py",
            ),
        )

    def test_default_init(self):
        """Test default initialization."""
        batch = TaskBatch(
            id="batch-001",
            name="Test Batch",
            batch_type=TaskType.FILE_SCAN,
        )
        assert batch.id == "batch-001"
        assert batch.task_count == 0

    def test_add_task(self, sample_task):
        """Test adding tasks to batch."""
        batch = TaskBatch(
            id="batch-001",
            name="Test Batch",
            batch_type=TaskType.FILE_SCAN,
        )
        batch.add_task(sample_task)
        assert batch.task_count == 1

    def test_can_add_task(self, sample_task):
        """Test can_add_task method."""
        batch = TaskBatch(
            id="batch-001",
            name="Test Batch",
            batch_type=TaskType.FILE_SCAN,
        )
        assert batch.can_add_task(sample_task, max_batch_size=5) is True

        # Add tasks with unique IDs up to limit
        for i in range(5):
            new_task = AgentTask(
                id=f"task-{i:03d}",
                task_type=TaskType.FILE_SCAN,
                context=TaskContext(
                    code_snippet="def foo(): pass",
                    language="python",
                    file_path=f"test{i}.py",
                ),
            )
            batch.add_task(new_task)

        assert batch.can_add_task(sample_task, max_batch_size=5) is False

    def test_get_combined_context(self, sample_task):
        """Test combined context generation."""
        batch = TaskBatch(
            id="batch-001",
            name="Test Batch",
            batch_type=TaskType.FILE_SCAN,
        )
        batch.add_task(sample_task)
        combined = batch.get_combined_context()
        assert "Task 1" in combined
        assert "test.py" in combined


class TestTaskGenerator:
    """Tests for TaskGenerator."""

    @pytest.fixture
    def generator(self):
        """Create a generator instance."""
        return TaskGenerator()

    @pytest.fixture
    def sample_target(self):
        """Create a sample audit target."""
        return AuditTarget(
            id="target-001",
            name="login_handler",
            target_type="entry_point",
            file_path="api/auth.py",
            entry_point_type="http",
            http_method="POST",
            endpoint_path="/api/login",
            auth_required=False,
            priority=AuditPriority(level=AuditPriorityLevel.HIGH),
        )

    def test_default_init(self, generator):
        """Test default initialization."""
        assert generator is not None
        assert TaskType.FILE_SCAN in generator.focus_vulnerabilities

    def test_generate_tasks_empty(self, generator):
        """Test generating tasks from empty list."""
        tasks = generator.generate_tasks([])
        assert len(tasks) == 0

    def test_generate_tasks_from_target(self, generator, sample_target):
        """Test generating tasks from a target."""
        tasks = generator.generate_tasks([sample_target])
        assert len(tasks) >= 1  # At least one task

        # Check task properties
        main_task = tasks[0]
        assert main_task.target_id == sample_target.id
        assert main_task.task_type == TaskType.ENTRY_POINT_ANALYSIS
        assert main_task.priority == TaskPriority.HIGH

    def test_skip_low_priority(self, generator):
        """Test that skip priority targets are skipped."""
        target = AuditTarget(
            id="target-001",
            name="test.py",
            target_type="file",
            file_path="tests/test_main.py",
            priority=AuditPriority(level=AuditPriorityLevel.SKIP),
        )
        tasks = generator.generate_tasks([target])
        assert len(tasks) == 0

    def test_determine_task_type_entry_point(self, generator, sample_target):
        """Test task type determination for entry points."""
        task_type = generator._determine_task_type(sample_target)
        assert task_type == TaskType.ENTRY_POINT_ANALYSIS

    def test_determine_task_type_auth_file(self, generator):
        """Test task type for auth files."""
        target = AuditTarget(
            id="target-001",
            name="auth.py",
            target_type="file",
            file_path="src/auth/login.py",
        )
        task_type = generator._determine_task_type(target)
        assert task_type == TaskType.AUTH_CHECK

    def test_create_batches(self, generator, sample_target):
        """Test batch creation."""
        tasks = generator.generate_tasks([sample_target, sample_target])
        batches = generator.create_batches(tasks)
        assert len(batches) >= 1

    def test_optimize_tasks(self, generator, sample_target):
        """Test task optimization."""
        tasks = generator.generate_tasks([sample_target])
        # Add multiple copies to test optimization
        tasks = tasks * 5
        optimized = generator.optimize_tasks(tasks, token_budget=10000)
        assert len(optimized) <= len(tasks)


class TestTaskDispatcher:
    """Tests for TaskDispatcher."""

    @pytest.fixture
    def dispatcher(self):
        """Create a dispatcher instance."""
        return TaskDispatcher(max_concurrent=2)

    @pytest.fixture
    def sample_task(self):
        """Create a sample task."""
        return AgentTask(
            id="task-001",
            task_type=TaskType.FILE_SCAN,
            context=TaskContext(
                code_snippet="def foo(): pass",
                language="python",
                file_path="test.py",
            ),
        )

    def test_default_init(self, dispatcher):
        """Test default initialization."""
        assert dispatcher.max_concurrent == 2
        assert dispatcher.pending_count == 0

    def test_add_task(self, dispatcher, sample_task):
        """Test adding tasks."""
        dispatcher.add_task(sample_task)
        assert dispatcher.pending_count == 1

    def test_add_tasks(self, dispatcher, sample_task):
        """Test adding multiple tasks."""
        dispatcher.add_tasks([sample_task, sample_task])
        assert dispatcher.pending_count == 2

    def test_sort_queue(self, dispatcher):
        """Test queue sorting by priority."""
        low_task = AgentTask(
            id="low",
            task_type=TaskType.FILE_SCAN,
            priority=TaskPriority.LOW,
            context=TaskContext(code_snippet="", language="python", file_path="a.py"),
        )
        high_task = AgentTask(
            id="high",
            task_type=TaskType.FILE_SCAN,
            priority=TaskPriority.HIGH,
            context=TaskContext(code_snippet="", language="python", file_path="b.py"),
        )

        dispatcher.add_tasks([low_task, high_task])
        dispatcher.sort_queue()

        # First in queue should be high priority
        tasks = list(dispatcher._pending)
        assert tasks[0].priority == TaskPriority.HIGH

    def test_get_statistics(self, dispatcher):
        """Test statistics retrieval."""
        stats = dispatcher.get_statistics()
        assert "total_tasks" in stats
        assert "completed" in stats
        assert "failed" in stats

    def test_cancel_task(self, dispatcher, sample_task):
        """Test task cancellation."""
        dispatcher.add_task(sample_task)
        result = dispatcher.cancel_task("task-001")
        assert result is True
        assert dispatcher.pending_count == 0

    def test_cancel_nonexistent_task(self, dispatcher):
        """Test cancelling a task that doesn't exist."""
        result = dispatcher.cancel_task("nonexistent")
        assert result is False

    @pytest.mark.asyncio
    async def test_execute_all(self, dispatcher, sample_task):
        """Test executing all tasks."""
        async def mock_executor(task):
            return TaskResult(task_id=task.id, success=True)

        dispatcher.add_task(sample_task)
        results = await dispatcher.execute_all(mock_executor)

        assert len(results) == 1
        assert dispatcher.completed_count == 1

    @pytest.mark.asyncio
    async def test_execute_with_failure(self, dispatcher, sample_task):
        """Test execution with failure."""
        async def failing_executor(task):
            raise RuntimeError("Test failure")

        dispatcher.add_task(sample_task)
        results = await dispatcher.execute_all(failing_executor)

        assert len(results) == 1
        assert dispatcher.failed_count == 1


class TestContextBuilder:
    """Tests for ContextBuilder."""

    @pytest.fixture
    def builder(self):
        """Create a context builder instance."""
        return ContextBuilder()

    def test_default_init(self, builder):
        """Test default initialization."""
        assert builder.max_context_size > 0
        assert builder.max_related_functions > 0

    def test_build_context_file_not_found(self, builder, tmp_path):
        """Test building context for nonexistent file."""
        context = builder.build_context(
            source_path=tmp_path,
            file_path="nonexistent.py",
        )
        assert context == ""

    def test_build_context_simple_file(self, builder, tmp_path):
        """Test building context from a simple file."""
        test_file = tmp_path / "test.py"
        test_file.write_text("def hello():\n    print('hello')\n")

        context = builder.build_context(
            source_path=tmp_path,
            file_path="test.py",
        )
        assert "hello" in context

    def test_extract_imports_python(self, builder):
        """Test extracting Python imports."""
        lines = [
            "import os",
            "from sys import path",
            "",
            "def main():",
            "    pass",
        ]
        imports = builder._extract_imports(lines)
        assert "import os" in imports
        assert "from sys import path" in imports

    def test_extract_function(self, builder):
        """Test extracting a function."""
        lines = [
            "def foo():",
            "    return 'hello'",
            "",
            "def bar():",
            "    pass",
        ]
        func = builder._extract_function(lines, "foo")
        assert "def foo():" in func
        assert "return 'hello'" in func

    def test_truncate_content(self, builder):
        """Test content truncation."""
        builder.max_context_size = 100
        long_content = "x" * 200
        truncated = builder._truncate_content(long_content)
        assert len(truncated) <= 120  # Some buffer for truncation message
        assert "truncated" in truncated

    def test_estimate_tokens(self, builder):
        """Test token estimation."""
        content = "hello world"  # 11 chars
        tokens = builder.estimate_tokens(content)
        assert tokens == 2  # 11 // 4 = 2

    def test_build_context_with_function_name(self, builder, tmp_path):
        """Test building context with function name."""
        test_file = tmp_path / "test.py"
        test_file.write_text("""
import os

def foo():
    return 'foo'

def bar():
    return foo()
""")

        context = builder.build_context(
            source_path=tmp_path,
            file_path="test.py",
            function_name="bar",
        )
        assert "def bar():" in context


class TestIntegration:
    """Integration tests for task module."""

    def test_generate_and_dispatch(self):
        """Test generating tasks and dispatching them."""
        # Create generator and dispatcher
        generator = TaskGenerator()
        dispatcher = TaskDispatcher(max_concurrent=2)

        # Create target
        target = AuditTarget(
            id="target-001",
            name="api.py",
            target_type="file",
            file_path="api/users.py",
            language="python",
            priority=AuditPriority(level=AuditPriorityLevel.HIGH),
        )

        # Generate tasks
        tasks = generator.generate_targets([target]) if hasattr(generator, 'generate_targets') else []
        # Note: generate_targets doesn't exist, use generate_tasks
        tasks = generator.generate_tasks([target])

        # Add to dispatcher
        dispatcher.add_tasks(tasks)

        assert dispatcher.pending_count == len(tasks)

    def test_task_batch_creation(self):
        """Test creating and using task batches."""
        generator = TaskGenerator()

        # Create multiple targets
        targets = [
            AuditTarget(
                id=f"target-{i}",
                name=f"file{i}.py",
                target_type="file",
                file_path=f"src/file{i}.py",
                priority=AuditPriority(level=AuditPriorityLevel.MEDIUM),
            )
            for i in range(5)
        ]

        # Generate tasks
        tasks = generator.generate_tasks(targets)

        # Create batches
        batches = generator.create_batches(tasks, max_batch_size=3)

        # Verify batches
        total_tasks = sum(b.task_count for b in batches)
        assert total_tasks == len(tasks)
