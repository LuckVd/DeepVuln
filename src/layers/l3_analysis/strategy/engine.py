"""
Strategy Engine

Generates and manages audit strategies based on target priorities.
"""

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
)
from src.layers.l3_analysis.strategy.calculator import PriorityCalculator
from src.layers.l3_analysis.strategy.models import (
    AuditPriorityLevel,
    AuditStrategy,
    AuditTarget,
    EngineAllocation,
    TargetGroup,
)


class StrategyEngine:
    """
    Generates audit strategies based on target priorities.

    The strategy engine:
    1. Converts attack surface data to audit targets
    2. Calculates priorities for each target
    3. Groups targets by priority level
    4. Allocates analysis engines to each group
    5. Generates a complete audit strategy
    """

    # Default engine allocations by priority level
    DEFAULT_ENGINE_ALLOCATIONS = {
        AuditPriorityLevel.CRITICAL: [
            EngineAllocation(
                engine="agent",
                concurrent=3,
                timeout_seconds=600,
                priority=1,
                required=True,
            ),
            EngineAllocation(
                engine="semgrep",
                rules=["security"],
                concurrent=5,
                timeout_seconds=300,
                priority=2,
            ),
            EngineAllocation(
                engine="codeql",
                queries=["security-and-quality"],
                concurrent=2,
                timeout_seconds=600,
                priority=3,
            ),
        ],
        AuditPriorityLevel.HIGH: [
            EngineAllocation(
                engine="agent",
                concurrent=2,
                timeout_seconds=300,
                priority=1,
            ),
            EngineAllocation(
                engine="semgrep",
                rules=["security"],
                concurrent=5,
                timeout_seconds=180,
                priority=2,
            ),
        ],
        AuditPriorityLevel.MEDIUM: [
            EngineAllocation(
                engine="semgrep",
                rules=["security"],
                concurrent=5,
                timeout_seconds=180,
                priority=1,
            ),
            EngineAllocation(
                engine="codeql",
                queries=["security-queries"],
                concurrent=2,
                timeout_seconds=300,
                priority=2,
            ),
        ],
        AuditPriorityLevel.LOW: [
            EngineAllocation(
                engine="semgrep",
                rules=["auto"],
                concurrent=10,
                timeout_seconds=120,
                priority=1,
            ),
        ],
        AuditPriorityLevel.SKIP: [],
    }

    def __init__(
        self,
        calculator: PriorityCalculator | None = None,
        custom_allocations: dict[AuditPriorityLevel, list[EngineAllocation]] | None = None,
        available_engines: list[str] | None = None,
    ):
        """
        Initialize the strategy engine.

        Args:
            calculator: Custom priority calculator.
            custom_allocations: Custom engine allocations by priority level.
            available_engines: List of available engines.
        """
        self.logger = get_logger(__name__)
        self.calculator = calculator or PriorityCalculator()
        self.engine_allocations = {**self.DEFAULT_ENGINE_ALLOCATIONS, **(custom_allocations or {})}
        self.available_engines = available_engines or ["semgrep", "codeql", "agent"]

    def create_strategy(
        self,
        source_path: Path,
        project_name: str | None = None,
        attack_surface: AttackSurfaceReport | None = None,
        additional_targets: list[AuditTarget] | None = None,
        settings: dict[str, Any] | None = None,
    ) -> AuditStrategy:
        """
        Create an audit strategy for a project.

        Args:
            source_path: Path to the source code.
            project_name: Project name (defaults to directory name).
            attack_surface: Attack surface analysis results.
            additional_targets: Additional targets to audit.
            settings: Strategy settings overrides.

        Returns:
            Complete audit strategy.
        """
        self.logger.info(f"Creating audit strategy for {source_path}")

        # Determine project name
        if not project_name:
            project_name = source_path.name

        # Collect all targets
        targets: list[AuditTarget] = []

        # Convert attack surface entry points to targets
        if attack_surface:
            entry_targets = self._convert_entry_points(attack_surface.entry_points)
            targets.extend(entry_targets)
            self.logger.info(f"Converted {len(entry_targets)} entry points to targets")

        # Add additional targets
        if additional_targets:
            targets.extend(additional_targets)

        # If no targets from attack surface, create file-based targets
        if not targets:
            targets = self._create_file_targets(source_path)
            self.logger.info(f"Created {len(targets)} file-based targets")

        # Calculate priorities
        targets = self.calculator.calculate_batch(targets)

        # Group targets by priority level
        groups = self._group_targets(targets)

        # Apply settings
        settings = settings or {}
        max_concurrent = settings.get("max_concurrent_engines", 3)
        stop_on_critical = settings.get("stop_on_critical", True)
        incremental_mode = settings.get("incremental_mode", False)
        max_timeout = settings.get("max_total_timeout_seconds", 3600)

        # Filter available engines from allocations
        groups = self._filter_engine_availability(groups)

        # Create strategy
        strategy = AuditStrategy(
            project_name=project_name,
            source_path=str(source_path),
            targets=targets,
            groups=groups,
            total_targets=len(targets),
            total_lines_of_code=sum(t.lines_of_code or 0 for t in targets),
            max_concurrent_engines=max_concurrent,
            max_total_timeout_seconds=max_timeout,
            available_engines=self.available_engines,
            stop_on_critical=stop_on_critical,
            incremental_mode=incremental_mode,
            created_at=datetime.now(UTC).isoformat(),
        )

        self.logger.info(
            f"Strategy created: {len(targets)} targets, "
            f"{len(groups)} groups, "
            f"critical: {len(strategy.get_critical_targets())}, "
            f"high: {len(strategy.get_high_targets())}"
        )

        return strategy

    def _convert_entry_points(self, entry_points: list[EntryPoint]) -> list[AuditTarget]:
        """
        Convert attack surface entry points to audit targets.

        Args:
            entry_points: List of entry points from attack surface analysis.

        Returns:
            List of audit targets.
        """
        targets = []

        for i, entry in enumerate(entry_points):
            target = AuditTarget(
                id=f"entry-{i:04d}",
                name=entry.handler,
                target_type="entry_point",
                file_path=entry.file,
                line_start=entry.line if entry.line > 0 else None,
                function_name=entry.handler,
                entry_point_type=entry.type.value,
                http_method=entry.method.value if entry.method else None,
                endpoint_path=entry.path,
                auth_required=entry.auth_required,
                params=entry.params,
                framework=entry.framework,
                tags=[entry.type.value],
                metadata={"middleware": entry.middleware} if entry.middleware else {},
            )
            targets.append(target)

        return targets

    def _create_file_targets(self, source_path: Path) -> list[AuditTarget]:
        """
        Create file-based targets when no entry points are available.

        Args:
            source_path: Path to source code.

        Returns:
            List of file-based audit targets.
        """
        targets = []

        # Source file extensions to include
        extensions = {".py", ".java", ".go", ".js", ".ts", ".jsx", ".tsx", ".php", ".rb", ".cs"}

        # Directories to skip
        skip_dirs = {
            "node_modules", "venv", ".venv", "env", ".env",
            "__pycache__", ".git", "dist", "build", "target",
            "vendor", "test", "tests", "__tests__", "testdata",
            "examples", "docs", ".idea", ".vscode",
        }

        for ext in extensions:
            for file_path in source_path.rglob(f"*{ext}"):
                # Skip excluded directories
                if any(part in skip_dirs for part in file_path.parts):
                    continue

                # Create target
                rel_path = file_path.relative_to(source_path)
                target = AuditTarget(
                    id=f"file-{len(targets):04d}",
                    name=file_path.name,
                    target_type="file",
                    file_path=str(rel_path),
                    language=self._detect_language(file_path),
                )

                # Count lines
                try:
                    content = file_path.read_text(encoding="utf-8")
                    target.lines_of_code = len(content.splitlines())
                except Exception:
                    pass

                targets.append(target)

        return targets

    def _detect_language(self, file_path: Path) -> str | None:
        """Detect programming language from file extension."""
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
        }
        return ext_to_lang.get(file_path.suffix)

    def _group_targets(self, targets: list[AuditTarget]) -> dict[str, TargetGroup]:
        """
        Group targets by priority level.

        Args:
            targets: List of targets with priorities calculated.

        Returns:
            Dictionary of target groups by priority level.
        """
        groups: dict[str, TargetGroup] = {}

        for level in AuditPriorityLevel:
            level_targets = [
                t for t in targets
                if t.priority and t.priority.level == level
            ]

            if not level_targets:
                continue

            # Get engine allocations for this level
            allocations = self.engine_allocations.get(level, [])
            # Deep copy allocations to avoid modifying defaults
            allocations = [a.model_copy() for a in allocations]

            # Determine concurrent limits based on target count
            max_concurrent = self._calculate_concurrency(len(level_targets), level)

            group = TargetGroup(
                priority_level=level,
                targets=level_targets,
                engine_allocations=allocations,
                max_concurrent_files=max_concurrent,
                timeout_seconds=self._calculate_timeout(len(level_targets), level),
            )

            groups[level.value] = group

        return groups

    def _calculate_concurrency(self, target_count: int, level: AuditPriorityLevel) -> int:
        """
        Calculate appropriate concurrency for a target group.

        Args:
            target_count: Number of targets in the group.
            level: Priority level of the group.

        Returns:
            Maximum concurrent files to process.
        """
        # Base concurrency by level
        base_concurrency = {
            AuditPriorityLevel.CRITICAL: 3,
            AuditPriorityLevel.HIGH: 5,
            AuditPriorityLevel.MEDIUM: 8,
            AuditPriorityLevel.LOW: 15,
            AuditPriorityLevel.SKIP: 0,
        }

        concurrent = base_concurrency.get(level, 5)

        # Adjust based on target count
        if target_count < 5:
            concurrent = min(concurrent, target_count)
        elif target_count > 50:
            concurrent = min(concurrent * 2, 20)

        return concurrent

    def _calculate_timeout(self, target_count: int, level: AuditPriorityLevel) -> int:
        """
        Calculate timeout for a target group.

        Args:
            target_count: Number of targets in the group.
            level: Priority level of the group.

        Returns:
            Timeout in seconds.
        """
        # Base timeout per target by level (seconds)
        base_timeout_per_target = {
            AuditPriorityLevel.CRITICAL: 120,
            AuditPriorityLevel.HIGH: 60,
            AuditPriorityLevel.MEDIUM: 30,
            AuditPriorityLevel.LOW: 15,
            AuditPriorityLevel.SKIP: 0,
        }

        per_target = base_timeout_per_target.get(level, 30)
        total = per_target * target_count

        # Apply minimum and maximum bounds
        min_timeout = 60
        max_timeout = 1800  # 30 minutes per group

        return max(min_timeout, min(total, max_timeout))

    def _filter_engine_availability(
        self,
        groups: dict[str, TargetGroup],
    ) -> dict[str, TargetGroup]:
        """
        Filter engine allocations based on availability.

        Args:
            groups: Target groups with engine allocations.

        Returns:
            Groups with filtered engine allocations.
        """
        for group in groups.values():
            # Filter out unavailable engines
            filtered = [
                alloc for alloc in group.engine_allocations
                if alloc.engine in self.available_engines
            ]
            group.engine_allocations = filtered

        return groups

    def optimize_strategy(
        self,
        strategy: AuditStrategy,
        time_budget_seconds: int | None = None,
        token_budget: int | None = None,
    ) -> AuditStrategy:
        """
        Optimize strategy based on resource constraints.

        Args:
            strategy: Strategy to optimize.
            time_budget_seconds: Maximum time allowed.
            token_budget: Maximum LLM tokens allowed.

        Returns:
            Optimized strategy.
        """
        if time_budget_seconds:
            strategy = self._optimize_for_time(strategy, time_budget_seconds)

        if token_budget:
            strategy = self._optimize_for_tokens(strategy, token_budget)

        return strategy

    def _optimize_for_time(
        self,
        strategy: AuditStrategy,
        time_budget: int,
    ) -> AuditStrategy:
        """Optimize strategy for time constraints."""
        # Calculate estimated time
        estimated_time = sum(g.timeout_seconds for g in strategy.groups.values())

        if estimated_time <= time_budget:
            return strategy

        self.logger.info(
            f"Optimizing strategy for time: {estimated_time}s > {time_budget}s budget"
        )

        # Reduce lower priority groups first
        levels_to_reduce = [
            AuditPriorityLevel.LOW,
            AuditPriorityLevel.MEDIUM,
        ]

        for level in levels_to_reduce:
            if level.value not in strategy.groups:
                continue

            if estimated_time <= time_budget:
                break

            group = strategy.groups[level.value]

            # Reduce agent allocations (most time-consuming)
            for alloc in group.engine_allocations:
                if alloc.engine == "agent":
                    alloc.concurrent = max(1, alloc.concurrent - 1)
                    alloc.timeout_seconds = max(60, alloc.timeout_seconds - 60)

            # Recalculate
            estimated_time = sum(g.timeout_seconds for g in strategy.groups.values())

        # If still over budget, skip low priority
        if estimated_time > time_budget:
            if AuditPriorityLevel.LOW.value in strategy.groups:
                del strategy.groups[AuditPriorityLevel.LOW.value]

        return strategy

    def _optimize_for_tokens(
        self,
        strategy: AuditStrategy,
        token_budget: int,
    ) -> AuditStrategy:
        """Optimize strategy for token constraints."""
        # Estimate token usage per target for agent
        TOKENS_PER_FILE_ESTIMATE = 5000  # Rough estimate

        # Count files that would use agent
        agent_targets = 0
        for group in strategy.groups.values():
            for alloc in group.engine_allocations:
                if alloc.engine == "agent":
                    agent_targets += len(group.targets)

        estimated_tokens = agent_targets * TOKENS_PER_FILE_ESTIMATE

        if estimated_tokens <= token_budget:
            return strategy

        self.logger.info(
            f"Optimizing strategy for tokens: {estimated_tokens} > {token_budget} budget"
        )

        # Reduce agent usage in lower priority groups
        levels_to_reduce = [
            AuditPriorityLevel.LOW,
            AuditPriorityLevel.MEDIUM,
            AuditPriorityLevel.HIGH,
        ]

        for level in levels_to_reduce:
            if estimated_tokens <= token_budget:
                break

            if level.value not in strategy.groups:
                continue

            group = strategy.groups[level.value]

            # Remove agent from this group
            group.engine_allocations = [
                alloc for alloc in group.engine_allocations
                if alloc.engine != "agent"
            ]

            # Recalculate
            agent_targets = 0
            for g in strategy.groups.values():
                for alloc in g.engine_allocations:
                    if alloc.engine == "agent":
                        agent_targets += len(g.targets)

            estimated_tokens = agent_targets * TOKENS_PER_FILE_ESTIMATE

        return strategy

    def get_execution_order(self, strategy: AuditStrategy) -> list[tuple[str, TargetGroup]]:
        """
        Get the order in which groups should be executed.

        Args:
            strategy: The audit strategy.

        Returns:
            List of (group_name, TargetGroup) tuples in execution order.
        """
        # Priority order for execution
        priority_order = [
            AuditPriorityLevel.CRITICAL,
            AuditPriorityLevel.HIGH,
            AuditPriorityLevel.MEDIUM,
            AuditPriorityLevel.LOW,
        ]

        order = []
        for level in priority_order:
            if level.value in strategy.groups:
                order.append((level.value, strategy.groups[level.value]))

        return order
