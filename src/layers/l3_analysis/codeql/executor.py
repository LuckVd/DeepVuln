"""
CodeQL Dataflow Executor - Execute CodeQL dataflow queries.

This module provides the execution layer for running custom CodeQL
dataflow queries and collecting the results.
"""

import asyncio
import json
import tempfile
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.codeql.query_generator import (
    TaintTrackingConfig,
    generate_taint_tracking_query,
)
from src.layers.l3_analysis.codeql.sarif_parser import (
    ParsedDataflowPath,
    SARIFParser,
)
from src.layers.l3_analysis.rounds.dataflow import (
    DataFlowPath,
    PathNode,
    Sanitizer,
    SanitizerType,
    SinkType,
    SourceType,
    TaintSink,
    TaintSource,
)

logger = get_logger(__name__)


@dataclass
class DataflowAnalysisConfig:
    """Configuration for CodeQL dataflow analysis."""

    # CodeQL settings
    codeql_path: str = "codeql"
    database_path: Path | None = None
    source_root: Path | None = None
    language: str = "python"

    # Execution settings
    timeout: int = 300
    max_concurrent_queries: int = 3

    # Analysis settings
    min_confidence: float = 0.3
    include_partial_paths: bool = True
    evaluate_sanitizers: bool = True


@dataclass
class DataflowResult:
    """Result of a CodeQL dataflow analysis."""

    # Analysis info
    query_id: str
    query_name: str
    source_path: str
    language: str

    # Results
    paths: list[DataFlowPath] = field(default_factory=list)
    parsed_paths: list[ParsedDataflowPath] = field(default_factory=list)

    # Statistics
    total_paths: int = 0
    complete_paths: int = 0
    paths_with_sanitizers: int = 0

    # Execution info
    execution_time_ms: float = 0.0
    success: bool = True
    error_message: str | None = None

    # Raw SARIF (for debugging)
    raw_sarif: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "query_id": self.query_id,
            "query_name": self.query_name,
            "source_path": self.source_path,
            "language": self.language,
            "total_paths": self.total_paths,
            "complete_paths": self.complete_paths,
            "paths_with_sanitizers": self.paths_with_sanitizers,
            "execution_time_ms": self.execution_time_ms,
            "success": self.success,
            "error_message": self.error_message,
        }


class CodeQLDataflowExecutor:
    """
    Executes CodeQL dataflow queries and collects results.

    This class handles:
    - Query file generation and execution
    - SARIF output parsing
    - Conversion to internal DataFlowPath model
    """

    def __init__(
        self,
        codeql_path: str = "codeql",
        database_path: Path | None = None,
        timeout: int = 300,
        source_root: Path | None = None,
    ):
        """
        Initialize the CodeQL dataflow executor.

        Args:
            codeql_path: Path to CodeQL CLI binary.
            database_path: Path to CodeQL database (if already created).
            timeout: Query execution timeout in seconds.
            source_root: Root directory of source code.
        """
        self.codeql_path = codeql_path
        self.database_path = database_path
        self.timeout = timeout
        self.source_root = source_root

        # Check CodeQL availability
        self._available = None

    async def is_available(self) -> bool:
        """Check if CodeQL CLI is available."""
        if self._available is not None:
            return self._available

        try:
            proc = await asyncio.create_subprocess_exec(
                self.codeql_path,
                "version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.wait(), timeout=10)
            self._available = proc.returncode == 0
        except Exception as e:
            logger.debug(f"CodeQL not available: {e}")
            self._available = False

        return self._available

    async def execute_query(
        self,
        config: TaintTrackingConfig,
        database_path: Path | None = None,
        output_dir: Path | None = None,
    ) -> DataflowResult:
        """
        Execute a CodeQL dataflow query.

        Args:
            config: TaintTracking configuration.
            database_path: Path to CodeQL database (overrides instance default).
            output_dir: Directory for temporary files.

        Returns:
            DataflowResult with analysis results.
        """
        db_path = database_path or self.database_path

        result = DataflowResult(
            query_id=config.query_id,
            query_name=config.query_name,
            source_path=str(self.source_root) if self.source_root else "",
            language=config.language,
        )

        start_time = datetime.now(UTC)

        try:
            # Check availability
            if not await self.is_available():
                result.success = False
                result.error_message = "CodeQL CLI is not available"
                return result

            # Check database
            if not db_path or not db_path.exists():
                result.success = False
                result.error_message = f"CodeQL database not found: {db_path}"
                return result

            # Create temporary directory for query
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)

                # Generate query file
                query_file = temp_path / "query.ql"
                query_content = generate_taint_tracking_query(config)
                query_file.write_text(query_content)

                # Output file for SARIF
                output_file = temp_path / "results.sarif"

                # Execute query
                cmd = [
                    self.codeql_path,
                    "database",
                    "analyze",
                    str(db_path),
                    str(query_file),
                    "--format", "sarif-latest",
                    "--output", str(output_file),
                    "--sarif-add-snippets",
                    "--timeout", str(self.timeout),
                ]

                logger.info(f"Executing CodeQL query: {config.query_id}")

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.timeout + 30
                )

                if proc.returncode != 0:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    logger.warning(f"CodeQL query returned non-zero: {error_msg}")
                    # Continue anyway - there might still be partial results

                # Parse SARIF output
                if output_file.exists():
                    sarif_content = json.loads(output_file.read_text())
                    result.raw_sarif = sarif_content

                    # Parse with enhanced parser
                    parser = SARIFParser(source_root=self.source_root)
                    result.parsed_paths = parser.parse(sarif_content)

                    # Convert to DataFlowPath model
                    result.paths = [
                        self._convert_to_dataflow_path(p, config)
                        for p in result.parsed_paths
                    ]

                    # Update statistics
                    result.total_paths = len(result.paths)
                    result.complete_paths = sum(1 for p in result.paths if p.is_complete)
                    result.paths_with_sanitizers = sum(1 for p in result.paths if p.has_effective_sanitizer)

                result.success = True
                logger.info(
                    f"CodeQL query completed: {result.total_paths} paths, "
                    f"{result.complete_paths} complete"
                )

        except asyncio.TimeoutError:
            result.success = False
            result.error_message = f"Query execution timed out after {self.timeout}s"
            logger.error(result.error_message)

        except Exception as e:
            result.success = False
            result.error_message = str(e)
            logger.error(f"CodeQL query execution failed: {e}")

        finally:
            end_time = datetime.now(UTC)
            result.execution_time_ms = (end_time - start_time).total_seconds() * 1000

        return result

    async def execute_batch(
        self,
        configs: list[TaintTrackingConfig],
        database_path: Path | None = None,
        max_concurrent: int = 3,
    ) -> list[DataflowResult]:
        """
        Execute multiple CodeQL queries in batch.

        Args:
            configs: List of TaintTracking configurations.
            database_path: Path to CodeQL database.
            max_concurrent: Maximum concurrent queries.

        Returns:
            List of DataflowResults.
        """
        semaphore = asyncio.Semaphore(max_concurrent)

        async def run_with_semaphore(config: TaintTrackingConfig) -> DataflowResult:
            async with semaphore:
                return await self.execute_query(config, database_path)

        tasks = [run_with_semaphore(config) for config in configs]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Handle exceptions
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(DataflowResult(
                    query_id=configs[i].query_id,
                    query_name=configs[i].query_name,
                    source_path="",
                    language=configs[i].language,
                    success=False,
                    error_message=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    def _convert_to_dataflow_path(
        self,
        parsed: ParsedDataflowPath,
        config: TaintTrackingConfig,
    ) -> DataFlowPath:
        """Convert ParsedDataflowPath to internal DataFlowPath model."""
        # Create source
        source = self._create_taint_source(parsed.source, config)

        # Create sink
        sink = self._create_taint_sink(parsed.sink, config)

        # Create path
        path = DataFlowPath(
            id=parsed.path_id,
            candidate_id=None,
            source=source,
            sink=sink,
            is_complete=parsed.is_complete,
            analyzer="codeql",
            path_confidence=0.9 if parsed.is_complete else 0.5,
        )

        # Add path nodes
        for loc in parsed.locations:
            node = PathNode(
                location=loc.to_code_location(),
                node_type=loc.node_type,
                variable_name=loc.variable_name,
                expression=loc.expression,
                function_name=loc.function_name,
            )
            path.add_node(node)

        # Add sanitizers
        for san_loc in parsed.sanitizer_locations:
            sanitizer = Sanitizer(
                id=f"san_{hash(str(san_loc)) % 100000:05d}",
                location=san_loc.to_code_location(),
                sanitizer_type=self._infer_sanitizer_type(san_loc.snippet or ""),
                function_name=san_loc.function_name,
            )
            path.sanitizers.append(sanitizer)

        if path.sanitizers:
            path.has_effective_sanitizer = any(s.effective for s in path.sanitizers)

        return path

    def _create_taint_source(
        self,
        path_loc: ParsedDataflowPath | None,
        config: TaintTrackingConfig,
    ) -> TaintSource:
        """Create TaintSource from parsed path location."""
        if path_loc and hasattr(path_loc, 'to_code_location'):
            loc = path_loc.to_code_location()
        else:
            from src.layers.l3_analysis.models import CodeLocation
            loc = CodeLocation(file="", line=1)

        # Infer source type from config
        source_type = self._map_source_type(config.source.category)

        return TaintSource(
            id=f"src_{config.query_id[:8]}",
            location=loc,
            source_type=source_type,
            user_controlled=True,
            variable_name=path_loc.variable_name if path_loc else None,
        )

    def _create_taint_sink(
        self,
        path_loc: ParsedDataflowPath | None,
        config: TaintTrackingConfig,
    ) -> TaintSink:
        """Create TaintSink from parsed path location."""
        if path_loc and hasattr(path_loc, 'to_code_location'):
            loc = path_loc.to_code_location()
        else:
            from src.layers.l3_analysis.models import CodeLocation
            loc = CodeLocation(file="", line=1)

        # Infer sink type from config
        sink_type = self._map_sink_type(config.sink.category)

        return TaintSink(
            id=f"sink_{config.query_id[:8]}",
            location=loc,
            sink_type=sink_type,
            dangerous_if_tainted=True,
            function_name=path_loc.function_name if path_loc else None,
        )

    def _map_source_type(self, category: str) -> SourceType:
        """Map category string to SourceType enum."""
        mapping = {
            "http_param": SourceType.HTTP_PARAM,
            "http_header": SourceType.HTTP_HEADER,
            "http_body": SourceType.HTTP_BODY,
            "http_cookie": SourceType.HTTP_COOKIE,
            "file_input": SourceType.FILE_INPUT,
            "user_input": SourceType.USER_INPUT,
            "env_var": SourceType.ENV_VAR,
            "command_arg": SourceType.COMMAND_ARG,
            "rpc_param": SourceType.RPC_PARAM,
        }
        return mapping.get(category.lower(), SourceType.USER_INPUT)

    def _map_sink_type(self, category: str) -> SinkType:
        """Map category string to SinkType enum."""
        mapping = {
            "sql_query": SinkType.SQL_QUERY,
            "command_exec": SinkType.COMMAND_EXEC,
            "http_response": SinkType.HTTP_RESPONSE,
            "file_read": SinkType.FILE_READ,
            "file_write": SinkType.FILE_WRITE,
            "http_redirect": SinkType.HTTP_REDIRECT,
            "ldap_query": SinkType.LDAP_QUERY,
            "xpath_query": SinkType.XPATH_QUERY,
            "template_render": SinkType.TEMPLATE_RENDER,
        }
        return mapping.get(category.lower(), SinkType.SQL_QUERY)

    def _infer_sanitizer_type(self, snippet: str) -> SanitizerType:
        """Infer sanitizer type from code snippet."""
        snippet_lower = snippet.lower()

        if any(kw in snippet_lower for kw in ["escape", "encode", "html"]):
            return SanitizerType.HTML_ENCODE
        if any(kw in snippet_lower for kw in ["prepare", "parameterize", "bind"]):
            return SanitizerType.PREPARED_STMT
        if any(kw in snippet_lower for kw in ["quote", "escape_string"]):
            return SanitizerType.SQL_ESCAPE
        if any(kw in snippet_lower for kw in ["validate", "check", "verify"]):
            return SanitizerType.INPUT_VALIDATE
        if any(kw in snippet_lower for kw in ["whitelist", "allow"]):
            return SanitizerType.WHITELIST
        if any(kw in snippet_lower for kw in ["int", "str", "float", "cast"]):
            return SanitizerType.TYPE_CAST

        return SanitizerType.INPUT_VALIDATE
