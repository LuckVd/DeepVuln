"""
Round Four Executor - Exploitability Verification

Fourth round of multi-round audit: verify vulnerability exploitability
and calibrate severity based on real-world attack feasibility.

For vulnerabilities that cannot be determined by static rules (NEEDS_REVIEW),
LLM-assisted assessment is available for more accurate judgment.
"""

import uuid
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pydantic import BaseModel, Field

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
)
from src.layers.l3_analysis.models import Finding, SeverityLevel
from src.layers.l3_analysis.prompts.exploitability import (
    build_exploitability_prompt,
    parse_exploitability_response,
)
from src.layers.l3_analysis.rounds.models import (
    AnalysisDepth,
    AuditSession,
    ConfidenceLevel,
    CoverageStats,
    EngineStats,
    RoundResult,
    RoundStatus,
    VulnerabilityCandidate,
)
from src.layers.l3_analysis.strategy.models import AuditStrategy
from src.layers.l3_analysis.task.context_builder import (
    CallChainInfo,
    ContextBuilder,
    DataFlowMarker,
)


class LLMClientProtocol(Protocol):
    """Protocol for LLM client interface."""

    async def complete_with_context(
        self,
        system_prompt: str,
        user_prompt: str,
        context: list[dict[str, str]] | None = None,
        **kwargs,
    ) -> "LLMResponse":
        """Generate completion from LLM."""
        ...


class LLMResponse:
    """Simplified LLM response type for protocol."""

    content: str
    usage: "TokenUsage"


class TokenUsage:
    """Token usage info."""

    prompt_tokens: int
    completion_tokens: int


class ExploitabilityStatus(str, Enum):
    """Status of exploitability verification."""

    EXPLOITABLE = "exploitable"  # Can be exploited in real attack
    CONDITIONAL = "conditional"  # Exploitable under specific conditions
    UNLIKELY = "unlikely"  # Unlikely to be exploitable
    NOT_EXPLOITABLE = "not_exploitable"  # Cannot be exploited
    NEEDS_REVIEW = "needs_review"  # Needs manual review


class SeverityAdjustment(BaseModel):
    """Record of a severity adjustment."""

    original_severity: SeverityLevel
    adjusted_severity: SeverityLevel
    reason: str
    factors: list[str] = Field(default_factory=list)


class ExploitabilityResult(BaseModel):
    """Result of exploitability verification for a single finding."""

    finding_id: str
    status: ExploitabilityStatus
    confidence: float = Field(ge=0.0, le=1.0)

    # Analysis results
    is_entry_point: bool = False
    entry_point_type: str | None = None
    is_user_controlled: bool = False
    data_source_type: str | None = None
    prerequisites: list[str] = Field(default_factory=list)

    # Severity adjustment
    severity_adjustment: SeverityAdjustment | None = None

    # Evidence
    call_chain: CallChainInfo | None = None
    data_flow_markers: list[DataFlowMarker] = Field(default_factory=list)

    # Reasoning
    reasoning: str = ""

    # Metadata
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class RoundFourExecutor:
    """
    Fourth round executor: Exploitability Verification.

    This round performs:
    1. Attack surface analysis (is code reachable?)
    2. Data source verification (is input user-controlled?)
    3. Prerequisite analysis (what conditions must be met?)
    4. Severity calibration (adjust based on real-world feasibility)
    """

    # Confidence threshold for auto-confirmation
    AUTO_CONFIRM_THRESHOLD = 0.85

    # Confidence threshold for auto-false-positive
    AUTO_FP_THRESHOLD = 0.25

    # Severity downgrade rules
    DOWNGRADE_RULES = {
        "no_entry_point": {
            "new_severity": SeverityLevel.INFO,
            "reason": "Code is not reachable from external entry points",
        },
        "internal_config_source": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Input comes from internal configuration, not user",
        },
        "trusted_source": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Input comes from trusted internal source",
        },
        "requires_auth": {
            "new_severity": None,  # Downgrade by one level
            "reason": "Exploitation requires authentication",
        },
        "requires_admin": {
            "new_severity": SeverityLevel.LOW,
            "reason": "Exploitation requires administrative privileges",
        },
        "framework_internal": {
            "new_severity": SeverityLevel.INFO,
            "reason": "This is internal framework code, not directly exploitable",
        },
        "rare_conditions": {
            "new_severity": None,  # Downgrade by one level
            "reason": "Exploitation requires rare/specific conditions",
        },
    }

    def __init__(
        self,
        source_path: Path,
        context_builder: ContextBuilder | None = None,
        llm_client: LLMClientProtocol | None = None,
        enable_llm_assessment: bool = True,
        attack_surface_report: AttackSurfaceReport | None = None,
    ):
        """
        Initialize the round four executor.

        Args:
            source_path: Path to source code.
            context_builder: Context builder instance (creates one if None).
            llm_client: LLM client for AI-assisted exploitability assessment.
            enable_llm_assessment: Whether to enable LLM-assisted assessment
                for NEEDS_REVIEW vulnerabilities.
            attack_surface_report: Pre-computed attack surface report from L1.
                When provided, this is used instead of ContextBuilder's
                simplified entry point detection for more accurate results.
        """
        self.logger = get_logger(__name__)
        self.source_path = source_path
        self._context_builder = context_builder or ContextBuilder()
        self._llm_client = llm_client
        self._enable_llm_assessment = enable_llm_assessment and llm_client is not None
        self._attack_surface_report = attack_surface_report

        # Build entry point lookup index for fast queries
        self._entry_point_index: dict[str, list[EntryPoint]] = {}
        # Track which files have entry points (for same-file matching)
        self._entry_point_files: set[str] = set()
        # Track imports in entry point files (for import-based matching)
        self._entry_point_imports: dict[str, list[str]] = {}

        if attack_surface_report:
            self._build_entry_point_index(attack_surface_report)
            self._build_entry_point_import_index()
            self.logger.info(
                f"Using pre-computed attack surface report with "
                f"{attack_surface_report.total_entry_points} entry points"
            )

        if self._enable_llm_assessment:
            self.logger.info("LLM-assisted exploitability assessment enabled")
        elif llm_client is None:
            self.logger.debug("No LLM client provided, LLM assessment disabled")
        else:
            self.logger.debug("LLM assessment explicitly disabled")

    def _build_entry_point_index(self, report: AttackSurfaceReport) -> None:
        """Build an index of entry points by file for fast lookup.

        Args:
            report: The attack surface report to index.
        """
        for entry in report.entry_points:
            # Index by file path
            file_key = entry.file
            if file_key not in self._entry_point_index:
                self._entry_point_index[file_key] = []
            self._entry_point_index[file_key].append(entry)

            # Track files with entry points
            self._entry_point_files.add(file_key)

            # Also index by handler name for function matching
            handler_key = entry.handler.lower()
            if handler_key not in self._entry_point_index:
                self._entry_point_index[handler_key] = []
            self._entry_point_index[handler_key].append(entry)

        self.logger.debug(
            f"Built entry point index with {len(self._entry_point_index)} keys, "
            f"{len(self._entry_point_files)} files with entry points"
        )

    def _build_entry_point_import_index(self) -> None:
        """Build an index of imports in entry point files.

        This allows us to check if a vulnerability file is imported by
        an entry point file, indicating potential reachability.
        """
        for file_path in self._entry_point_files:
            try:
                full_path = self.source_path / file_path
                if not full_path.exists():
                    continue

                content = full_path.read_text(encoding="utf-8", errors="ignore")
                imports = self._extract_imports(content)

                if imports:
                    self._entry_point_imports[file_path] = imports

            except Exception as e:
                self.logger.debug(f"Failed to extract imports from {file_path}: {e}")

        self.logger.debug(
            f"Built import index for {len(self._entry_point_imports)} entry point files"
        )

    def _extract_imports(self, content: str) -> list[str]:
        """Extract import statements from Python code.

        Args:
            content: Source code content.

        Returns:
            List of imported module/file names.
        """
        import re

        imports = []

        # Python: from X import Y
        for match in re.finditer(r'from\s+([\w.]+)\s+import', content):
            module = match.group(1)
            imports.append(module)

        # Python: import X
        for match in re.finditer(r'import\s+([\w.]+)', content):
            module = match.group(1)
            imports.append(module)

        # Java: import com.example.X
        for match in re.finditer(r'import\s+([\w.]+)', content):
            module = match.group(1)
            if module not in imports:
                imports.append(module)

        return imports

    def _is_imported_by_entry_point_file(self, file_path: str) -> tuple[bool, str | None]:
        """Check if a file is imported by any entry point file.

        Args:
            file_path: File path to check.

        Returns:
            Tuple of (is_imported, importing_entry_file).
        """
        if not self._entry_point_imports:
            return False, None

        # Extract module name from file path
        # e.g., "copyparty/authsrv.py" -> "authsrv" or "copyparty.authsrv"
        file_module = file_path.replace("/", ".").replace("\\", ".")
        if file_module.endswith(".py"):
            file_module = file_module[:-3]

        # Also try just the base name
        base_name = file_path.split("/")[-1].replace(".py", "")

        for entry_file, imports in self._entry_point_imports.items():
            for imp in imports:
                # Check if the import matches the file
                if imp == file_module or imp.endswith(f".{base_name}") or imp == base_name:
                    return True, entry_file
                # Check partial match (e.g., "authsrv" in "copyparty.authsrv")
                if base_name in imp.split("."):
                    return True, entry_file

        return False, None

    def _find_entry_point(
        self,
        file_path: str,
        function_name: str | None,
    ) -> EntryPoint | None:
        """Find an entry point matching the given file and function.

        Args:
            file_path: File path to search for.
            function_name: Function name to search for.

        Returns:
            Matching EntryPoint or None if not found.
        """
        if not self._entry_point_index:
            return None

        # Try to find by file path first
        entries = self._entry_point_index.get(file_path, [])
        if entries and function_name:
            # Look for matching handler
            func_lower = function_name.lower()
            for entry in entries:
                if entry.handler.lower() == func_lower:
                    return entry
            # Return first entry for this file if no exact match
            return entries[0] if entries else None

        # Try to find by handler name
        if function_name:
            handler_key = function_name.lower()
            entries = self._entry_point_index.get(handler_key, [])
            if entries:
                return entries[0]

        return None

    def _is_in_attack_surface(
        self,
        file_path: str,
        function_name: str | None,
    ) -> tuple[bool, str | None]:
        """Check if the file/function is in the pre-computed attack surface.

        Uses a tiered matching strategy:
        1. Exact match: function is an entry point handler
        2. Same-file match: function is in a file with entry points
        3. Import-based match: file is imported by an entry point file

        Args:
            file_path: File path to check.
            function_name: Function name to check.

        Returns:
            Tuple of (is_entry_point, entry_point_type).
        """
        # Map EntryPointType to string
        type_map = {
            EntryPointType.HTTP: "HTTP",
            EntryPointType.RPC: "RPC",
            EntryPointType.GRPC: "gRPC",
            EntryPointType.MQ: "MQ",
            EntryPointType.CRON: "SCHEDULED",
            EntryPointType.FILE: "FILE",
            EntryPointType.WEBSOCKET: "WEBSOCKET",
            EntryPointType.CLI: "CLI",
        }

        # Tier 1: Exact match
        entry = self._find_entry_point(file_path, function_name)
        if entry:
            return True, type_map.get(entry.type, entry.type.value)

        # Tier 2: Same-file match
        # If the vulnerability is in a file that contains entry points,
        # it's likely reachable
        if file_path in self._entry_point_files:
            # Find the entry type from this file
            entries = self._entry_point_index.get(file_path, [])
            if entries:
                entry_type = type_map.get(entries[0].type, "HTTP")
                self.logger.debug(
                    f"Same-file match: {function_name} in {file_path} "
                    f"(file has {len(entries)} entry points)"
                )
                return True, f"{entry_type}_SAME_FILE"
            return True, "SAME_FILE"

        # Tier 3: Import-based match
        # If the vulnerability file is imported by an entry point file,
        # it may be reachable
        is_imported, importing_file = self._is_imported_by_entry_point_file(file_path)
        if is_imported and importing_file:
            # Find the entry type from the importing file
            entries = self._entry_point_index.get(importing_file, [])
            if entries:
                entry_type = type_map.get(entries[0].type, "HTTP")
                self.logger.debug(
                    f"Import-based match: {file_path} imported by {importing_file}"
                )
                return True, f"{entry_type}_IMPORTED"

        return False, None

    async def execute(
        self,
        strategy: AuditStrategy,
        previous_round: RoundResult | None = None,
    ) -> RoundResult:
        """
        Execute round four: Exploitability Verification.

        Args:
            strategy: Audit strategy with targets.
            previous_round: Result from round three (contains candidates).

        Returns:
            Round result with verified/adjusted findings.
        """
        self.logger.info("Starting Round 4: Exploitability Verification")

        # Initialize round result
        round_result = RoundResult(
            round_number=4,
            status=RoundStatus.RUNNING,
            started_at=datetime.now(UTC),
        )

        # Initialize coverage stats
        coverage = CoverageStats(
            total_targets=strategy.total_targets,
        )

        # Initialize engine stats
        engine_stats = EngineStats(
            engine="exploitability-verifier",
            enabled=True,
            executed=True,
            start_time=datetime.now(UTC),
        )

        try:
            # Get candidates from previous round
            if not previous_round or not previous_round.candidates:
                self.logger.info("No candidates to verify in Round 4")
                round_result.status = RoundStatus.SKIPPED
                round_result.mark_completed()
                return round_result

            candidates = previous_round.candidates
            coverage.total_targets = len(candidates)

            self.logger.info(f"Verifying exploitability for {len(candidates)} candidates")

            # Process each candidate
            for candidate in candidates:
                try:
                    result = await self._verify_exploitability(candidate)

                    # Update candidate based on result
                    self._apply_verification_result(candidate, result)

                    # Add to round result
                    round_result.add_candidate(candidate)
                    coverage.analyzed_targets += 1

                    # Track for next round if needed
                    if result.status == ExploitabilityStatus.NEEDS_REVIEW:
                        round_result.next_round_candidates.append(candidate.id)

                except Exception as e:
                    self.logger.warning(f"Error verifying {candidate.id}: {e}")
                    candidate.add_evidence("exploitability_verification", {
                        "error": str(e),
                        "status": "error",
                    })

            # Update engine stats
            engine_stats.end_time = datetime.now(UTC)
            engine_stats.duration_seconds = (
                engine_stats.end_time - engine_stats.start_time
            ).total_seconds()
            engine_stats.targets_analyzed = coverage.analyzed_targets

            # Complete round
            round_result.coverage = coverage
            round_result.engine_stats["exploitability-verifier"] = engine_stats
            round_result.mark_completed()

            self.logger.info(
                f"Round 4 completed: {coverage.analyzed_targets} verified, "
                f"{len(round_result.next_round_candidates)} need manual review"
            )

            return round_result

        except Exception as e:
            self.logger.error(f"Round 4 failed: {e}")
            round_result.mark_failed(str(e))
            return round_result

    async def _verify_exploitability(
        self,
        candidate: VulnerabilityCandidate,
    ) -> ExploitabilityResult:
        """
        Verify exploitability of a single vulnerability candidate.

        Args:
            candidate: The vulnerability candidate to verify.

        Returns:
            ExploitabilityResult with verification details.
        """
        finding = candidate.finding
        location = finding.location

        # Get function name - prefer location.function, fallback to extracting from snippet
        function_name = location.function or self._extract_function_name(location.snippet or "")

        # First, check if this is in the pre-computed attack surface
        is_entry_from_report, entry_type_from_report = self._is_in_attack_surface(
            location.file, function_name
        )

        # Get call chain analysis (still useful for finding callers)
        call_chain = self._context_builder.analyze_call_chain(
            source_path=self.source_path,
            file_path=location.file,
            function_name=function_name,
        )

        # If we have a pre-computed attack surface report, use it to enhance call_chain
        if is_entry_from_report and call_chain:
            # Override entry point info with more accurate data from L1
            call_chain.is_entry_point = True
            call_chain.entry_point_type = entry_type_from_report
            self.logger.debug(
                f"Enhanced call_chain with L1 data: {function_name} is {entry_type_from_report}"
            )
        elif is_entry_from_report and not call_chain:
            # Create a minimal CallChainInfo from the report data
            call_chain = CallChainInfo(
                function_name=function_name or "unknown",
                file_path=location.file,
                callers=[],
                is_entry_point=True,
                entry_point_type=entry_type_from_report,
            )

        # Get data flow analysis
        data_flow = self._context_builder.analyze_data_flow(
            source_path=self.source_path,
            file_path=location.file,
            function_name=function_name,
        )

        # Determine exploitability using static rules
        status, confidence, reasoning = self._assess_exploitability(
            call_chain=call_chain,
            data_flow=data_flow,
            finding=finding,
        )

        # If NEEDS_REVIEW and LLM is available, use LLM-assisted assessment
        if status == ExploitabilityStatus.NEEDS_REVIEW and self._enable_llm_assessment:
            self.logger.info(
                f"Using LLM-assisted assessment for {finding.title} (NEEDS_REVIEW)"
            )

            llm_result = await self._llm_assisted_assessment(
                candidate=candidate,
                call_chain=call_chain,
                data_flow=data_flow,
            )

            if llm_result:
                status = llm_result.get("status", status)
                confidence = llm_result.get("confidence", confidence)
                reasoning = llm_result.get("reasoning", reasoning)

                # Ensure status is valid enum value
                try:
                    status = ExploitabilityStatus(status)
                except ValueError:
                    self.logger.warning(
                        f"Invalid LLM status '{status}', keeping NEEDS_REVIEW"
                    )
                    status = ExploitabilityStatus.NEEDS_REVIEW

                self.logger.info(
                    f"LLM assessment result: {status.value} (confidence: {confidence})"
                )

        # Determine severity adjustment
        severity_adjustment = self._calculate_severity_adjustment(
            original_severity=finding.severity,
            call_chain=call_chain,
            data_flow=data_flow,
            status=status,
        )

        return ExploitabilityResult(
            finding_id=finding.id,
            status=status,
            confidence=confidence,
            is_entry_point=call_chain.is_entry_point if call_chain else False,
            entry_point_type=call_chain.entry_point_type if call_chain else None,
            is_user_controlled=self._has_user_controlled_data(data_flow),
            data_source_type=self._get_primary_data_source(data_flow),
            prerequisites=self._extract_prerequisites(call_chain, data_flow),
            severity_adjustment=severity_adjustment,
            call_chain=call_chain,
            data_flow_markers=data_flow,
            reasoning=reasoning,
        )

    async def _llm_assisted_assessment(
        self,
        candidate: VulnerabilityCandidate,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
    ) -> dict[str, Any] | None:
        """
        Use LLM to assess exploitability when static rules are inconclusive.

        Args:
            candidate: The vulnerability candidate to assess.
            call_chain: Call chain analysis results.
            data_flow: Data flow markers.

        Returns:
            Dict with 'status', 'confidence', 'reasoning' or None on failure.
        """
        if not self._llm_client:
            return None

        finding = candidate.finding
        location = finding.location

        # Build finding dict for prompt
        finding_dict = {
            "type": finding.rule_id or "unknown",
            "title": finding.title,
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "location": location.to_display() if location else "Unknown",
            "description": finding.description,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
        }

        # Build call chain dict for prompt
        call_chain_dict = None
        if call_chain:
            call_chain_dict = {
                "is_entry_point": call_chain.is_entry_point,
                "entry_point_type": call_chain.entry_point_type,
                "callers": [
                    {"name": c.get("name"), "file": c.get("file")}
                    for c in (call_chain.callers or [])
                ],
            }

        # Build data flow list for prompt
        data_flow_list = None
        if data_flow:
            data_flow_list = [
                {
                    "variable": m.variable_name,
                    "source_type": m.source_type,
                    "line": m.source_location,
                }
                for m in data_flow
            ]

        # Get source code for context
        source_code = None
        try:
            file_path = self.source_path / location.file
            if file_path.exists():
                source_code = file_path.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            self.logger.warning(f"Could not read source file: {e}")

        # Build prompts
        try:
            system_prompt, user_prompt = build_exploitability_prompt(
                finding=finding_dict,
                call_chain=call_chain_dict,
                data_flow=data_flow_list,
                source_code=source_code,
            )
        except Exception as e:
            self.logger.error(f"Failed to build exploitability prompt: {e}")
            return None

        # Call LLM
        try:
            response = await self._llm_client.complete_with_context(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                context=None,
                temperature=0.1,  # Low temperature for consistent results
                max_tokens=1000,
            )

            # Extract content from response
            response_text = response.content if hasattr(response, 'content') else str(response)

            # Parse response
            result = parse_exploitability_response(response_text)

            if result:
                # Validate and normalize the result
                status = result.get("status", "needs_review")
                confidence = result.get("confidence", 0.5)

                # Ensure confidence is within bounds
                try:
                    confidence = float(confidence)
                    confidence = max(0.0, min(1.0, confidence))
                except (TypeError, ValueError):
                    confidence = 0.5

                # Map LLM status to our enum
                status_mapping = {
                    "exploitable": ExploitabilityStatus.EXPLOITABLE,
                    "conditional": ExploitabilityStatus.CONDITIONAL,
                    "unlikely": ExploitabilityStatus.UNLIKELY,
                    "not_exploitable": ExploitabilityStatus.NOT_EXPLOITABLE,
                    "needs_review": ExploitabilityStatus.NEEDS_REVIEW,
                }

                if status.lower() in status_mapping:
                    status = status_mapping[status.lower()]
                else:
                    status = ExploitabilityStatus.NEEDS_REVIEW

                return {
                    "status": status,
                    "confidence": confidence,
                    "reasoning": result.get("reasoning", "LLM assessment"),
                    "entry_point_analysis": result.get("entry_point_analysis"),
                    "data_source_analysis": result.get("data_source_analysis"),
                    "attack_scenario": result.get("attack_scenario"),
                    "prerequisites": result.get("prerequisites", []),
                }

            return None

        except Exception as e:
            self.logger.error(f"LLM-assisted assessment failed: {e}")
            return None

    def _assess_exploitability(
        self,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
        finding: Finding,
    ) -> tuple[ExploitabilityStatus, float, str]:
        """
        Assess the exploitability of a finding.

        Returns:
            Tuple of (status, confidence, reasoning).
        """
        reasoning_parts = []

        # Check 1: Is this code reachable from external entry points?
        if call_chain:
            if call_chain.is_entry_point:
                entry_type = call_chain.entry_point_type or "unknown"
                reasoning_parts.append(
                    f"Code IS an external entry point ({entry_type})."
                )
            elif call_chain.callers:
                reasoning_parts.append(
                    f"Code is called by {len(call_chain.callers)} other functions."
                )
                # Check if any caller is an entry point
                has_entry_caller = any(
                    self._is_entry_caller(c) for c in call_chain.callers
                )
                if not has_entry_caller:
                    reasoning_parts.append("No external entry points found in call chain.")
            else:
                reasoning_parts.append("No external callers found - may be internal/dead code.")
        else:
            reasoning_parts.append("Could not determine call chain.")

        # Check 2: Is the input user-controlled?
        user_controlled = self._has_user_controlled_data(data_flow)
        if user_controlled:
            reasoning_parts.append("Input appears to be USER-CONTROLLED.")
        else:
            sources = [m.source_type for m in data_flow if m.source_type]
            if "config" in sources:
                reasoning_parts.append("Input comes from CONFIGURATION (not user-controlled).")
            elif "trusted" in sources:
                reasoning_parts.append("Input comes from TRUSTED source.")
            elif not data_flow:
                reasoning_parts.append("Could not determine data sources.")
            else:
                reasoning_parts.append("No user-controlled input path found.")

        # Filter out None values from reasoning_parts
        reasoning_parts = [str(p) for p in reasoning_parts if p is not None]
        reasoning_base = " | ".join(reasoning_parts)

        # Check 3: Determine final status
        if not call_chain or (not call_chain.is_entry_point and not call_chain.callers):
            # No entry point found
            return (
                ExploitabilityStatus.NOT_EXPLOITABLE,
                0.2,
                reasoning_base + " | Severity should be INFO."
            )

        if not user_controlled:
            # Input not user-controlled
            if call_chain.is_entry_point:
                return (
                    ExploitabilityStatus.UNLIKELY,
                    0.4,
                    reasoning_base + " | Entry point exists but input is not user-controlled."
                )
            else:
                return (
                    ExploitabilityStatus.NOT_EXPLOITABLE,
                    0.25,
                    reasoning_base + " | No user-controlled input path found."
                )

        if call_chain.is_entry_point and user_controlled:
            return (
                ExploitabilityStatus.EXPLOITABLE,
                0.85,
                reasoning_base + " | REAL VULNERABILITY - externally reachable with user input."
            )

        # Default: needs review
        return (
            ExploitabilityStatus.NEEDS_REVIEW,
            0.5,
            reasoning_base + " | Could not determine exploitability - needs manual review."
        )

    def _calculate_severity_adjustment(
        self,
        original_severity: SeverityLevel,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
        status: ExploitabilityStatus,
    ) -> SeverityAdjustment | None:
        """
        Calculate severity adjustment based on exploitability analysis.

        Returns:
            SeverityAdjustment if adjustment is needed, None otherwise.
        """
        factors = []
        new_severity = original_severity
        reason = ""

        # Factor 1: No entry point
        if call_chain and not call_chain.is_entry_point and not call_chain.callers:
            rule = self.DOWNGRADE_RULES["no_entry_point"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("no_entry_point")

        # Factor 2: Internal config source
        elif self._has_only_config_sources(data_flow):
            rule = self.DOWNGRADE_RULES["internal_config_source"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("internal_config_source")

        # Factor 3: Trusted source
        elif self._has_only_trusted_sources(data_flow):
            rule = self.DOWNGRADE_RULES["trusted_source"]
            new_severity = rule["new_severity"]
            reason = rule["reason"]
            factors.append("trusted_source")

        # Factor 4: Based on exploitability status
        elif status == ExploitabilityStatus.NOT_EXPLOITABLE:
            new_severity = SeverityLevel.INFO
            reason = "Vulnerability is not exploitable"
            factors.append("not_exploitable")
        elif status == ExploitabilityStatus.UNLIKELY:
            new_severity = self._downgrade_one_level(original_severity)
            reason = "Exploitation is unlikely"
            factors.append("unlikely_exploitation")

        # No adjustment needed
        if new_severity == original_severity:
            return None

        return SeverityAdjustment(
            original_severity=original_severity,
            adjusted_severity=new_severity,
            reason=reason,
            factors=factors,
        )

    def _apply_verification_result(
        self,
        candidate: VulnerabilityCandidate,
        result: ExploitabilityResult,
    ) -> None:
        """Apply verification result to a candidate."""
        # Add evidence
        candidate.add_evidence("exploitability_verification", {
            "status": result.status.value,
            "confidence": result.confidence,
            "is_entry_point": result.is_entry_point,
            "is_user_controlled": result.is_user_controlled,
            "reasoning": result.reasoning,
        })

        # Apply severity adjustment
        if result.severity_adjustment:
            adj = result.severity_adjustment
            candidate.finding.severity = adj.adjusted_severity
            candidate.finding.metadata = candidate.finding.metadata or {}
            candidate.finding.metadata["severity_adjustment"] = {
                "original": adj.original_severity.value,
                "adjusted": adj.adjusted_severity.value,
                "reason": adj.reason,
                "factors": adj.factors,
            }

            self.logger.info(
                f"Adjusted severity for {candidate.finding.title}: "
                f"{adj.original_severity.value} -> {adj.adjusted_severity.value} "
                f"({adj.reason})"
            )

        # Update confidence
        if result.confidence >= 0.8:
            candidate.confidence = ConfidenceLevel.HIGH
        elif result.confidence >= 0.5:
            candidate.confidence = ConfidenceLevel.MEDIUM
        else:
            candidate.confidence = ConfidenceLevel.LOW

        # Mark for verification if needed
        candidate.needs_verification = (
            result.status == ExploitabilityStatus.NEEDS_REVIEW
        )

    # =========================================================================
    # Helper Methods
    # =========================================================================

    def _extract_function_name(self, code_snippet: str) -> str | None:
        """Extract function name from code snippet."""
        import re

        # Try to find function definition
        patterns = [
            r'def\s+(\w+)\s*\(',  # Python
            r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\(',  # Java
            r'function\s+(\w+)\s*\(',  # JavaScript
            r'func\s+(\w+)\s*\(',  # Go
        ]

        for pattern in patterns:
            match = re.search(pattern, code_snippet)
            if match:
                return match.group(1)

        return None

    def _has_user_controlled_data(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if any data flow marker indicates user-controlled input."""
        return any(m.source_type == "user_input" for m in data_flow)

    def _get_primary_data_source(self, data_flow: list[DataFlowMarker]) -> str | None:
        """Get the primary data source type."""
        if not data_flow:
            return None

        # Priority: user_input > config > trusted > internal
        priority = ["user_input", "config", "trusted", "internal"]
        for source_type in priority:
            if any(m.source_type == source_type for m in data_flow):
                return source_type

        return data_flow[0].source_type if data_flow else None

    def _has_only_config_sources(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if all data sources are configuration."""
        if not data_flow:
            return False
        return all(m.source_type in ("config", "internal") for m in data_flow)

    def _has_only_trusted_sources(self, data_flow: list[DataFlowMarker]) -> bool:
        """Check if all data sources are trusted."""
        if not data_flow:
            return False
        return all(m.source_type in ("trusted", "internal") for m in data_flow)

    def _is_entry_caller(self, caller: dict[str, str]) -> bool:
        """Check if a caller function is an entry point."""
        # Common entry point patterns
        entry_patterns = [
            "main", "handle", "process", "execute", "run",
            "onMessage", "onRequest", "doGet", "doPost",
            "controller", "handler", "endpoint",
        ]
        name = caller.get("name", "").lower()
        return any(p in name for p in entry_patterns)

    def _extract_prerequisites(
        self,
        call_chain: CallChainInfo | None,
        data_flow: list[DataFlowMarker],
    ) -> list[str]:
        """Extract prerequisites for exploitation."""
        prerequisites = []

        if call_chain and not call_chain.is_entry_point:
            prerequisites.append("Must reach internal function through call chain")

        if data_flow:
            for marker in data_flow:
                if marker.source_type == "config":
                    prerequisites.append("Must control configuration values")
                elif marker.source_type == "trusted":
                    prerequisites.append("Must compromise trusted data source")

        return prerequisites

    def _downgrade_one_level(self, severity: SeverityLevel) -> SeverityLevel:
        """Downgrade severity by one level."""
        downgrade_map = {
            SeverityLevel.CRITICAL: SeverityLevel.HIGH,
            SeverityLevel.HIGH: SeverityLevel.MEDIUM,
            SeverityLevel.MEDIUM: SeverityLevel.LOW,
            SeverityLevel.LOW: SeverityLevel.INFO,
            SeverityLevel.INFO: SeverityLevel.INFO,
        }
        return downgrade_map.get(severity, severity)
