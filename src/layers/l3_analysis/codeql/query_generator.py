"""
CodeQL Query Generator - Generate dataflow queries from vulnerability candidates.

This module generates customized CodeQL queries based on vulnerability findings,
including source/sink definitions and TaintTracking configurations.
"""

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.models import Finding

logger = get_logger(__name__)


class VulnerabilityCategory(str, Enum):
    """Categories of vulnerabilities for query generation."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    OPEN_REDIRECT = "open_redirect"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    TEMPLATE_INJECTION = "template_injection"
    DESERIALIZATION = "deserialization"
    GENERIC = "generic"


@dataclass
class SourceDefinition:
    """Definition of a taint source for CodeQL query."""

    # Source identification
    name: str
    category: str  # http_param, user_input, file_input, etc.

    # Location info
    file_path: str | None = None
    function_name: str | None = None
    parameter_name: str | None = None
    variable_name: str | None = None
    line: int | None = None

    # CodeQL predicate
    predicate_code: str = ""

    def to_codeql(self, language: str) -> str:
        """Generate CodeQL predicate for this source."""
        if self.predicate_code:
            return self.predicate_code

        # Generate based on category and language
        if language == "python":
            return self._to_python_source()
        elif language == "java":
            return self._to_java_source()
        elif language in ("javascript", "typescript"):
            return self._to_js_source()
        elif language == "go":
            return self._to_go_source()
        else:
            return self._to_generic_source()

    def _to_python_source(self) -> str:
        """Generate Python-specific source predicate."""
        if self.category == "http_param":
            if self.parameter_name:
                return f'''isSource(data: DataFlow::Node) {{
  exists(HandlerCall hc, Argument a |
    a = hc.getArg(0).getAttribute("args") and
    data = a.getAttribute("{self.parameter_name}")
  )
}}'''
            return '''isSource(data: DataFlow::Node) {
  exists(HandlerCall hc |
    data = hc.getArg(0).getAttribute("args").getAttribute(_)
  )
}'''

        if self.category == "user_input":
            if self.function_name and self.parameter_name:
                return f'''isSource(data: DataFlow::Node) {{
  exists(Function f, Parameter p |
    f.getName() = "{self.function_name}" and
    p = f.getArg(0) and
    data = p.getAnAttribute()
  )
}}'''

        # Generic input source
        return '''isSource(data: DataFlow::Node) {
  data instanceof UserInputNode
}'''

    def _to_java_source(self) -> str:
        """Generate Java-specific source predicate."""
        if self.category == "http_param":
            if self.parameter_name:
                return f'''isSource(data: DataFlow::Node) {{
  exists(HttpServletRequest req, MethodCall mc |
    mc.getMethod().hasName("getParameter") and
    mc.getArgument(0).getStringValue() = "{self.parameter_name}" and
    data = mc
  )
}}'''
            return '''isSource(data: DataFlow::Node) {
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    mc.getMethod().hasName("getParameter") and
    data = mc
  )
}'''

        return '''isSource(data: DataFlow::Node) {
  data instanceof RemoteUserInput
}'''

    def _to_js_source(self) -> str:
        """Generate JavaScript-specific source predicate."""
        if self.category == "http_param":
            if self.parameter_name:
                return f'''isSource(data: DataFlow::Node) {{
  exists(DataFlow::CallCfgNode call |
    call = API::getRequest().getArgument(0).getField("query").getField("{self.parameter_name}") and
    data = call
  )
}}'''
            return '''isSource(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::getRequest().getArgument(0).getField("query").getField(_)
  )
}'''

        return '''isSource(data: DataFlow::Node) {
  data instanceof UserInputNode
}'''

    def _to_go_source(self) -> str:
        """Generate Go-specific source predicate."""
        if self.category == "http_param":
            return '''isSource(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::httpRequestParam().getACall() and
    data = call
  )
}'''

        return '''isSource(data: DataFlow::Node) {
  data instanceof UserInputNode
}'''

    def _to_generic_source(self) -> str:
        """Generate generic source predicate."""
        return '''isSource(data: DataFlow::Node) {
  data instanceof UserInputNode
}'''


@dataclass
class SinkDefinition:
    """Definition of a sensitive sink for CodeQL query."""

    # Sink identification
    name: str
    category: str  # sql_query, command_exec, file_write, http_response, etc.

    # Location info
    file_path: str | None = None
    function_name: str | None = None
    method_name: str | None = None
    class_name: str | None = None
    line: int | None = None

    # Sink details
    argument_position: int | None = None
    vulnerable_functions: list[str] = field(default_factory=list)

    # CodeQL predicate
    predicate_code: str = ""

    def to_codeql(self, language: str) -> str:
        """Generate CodeQL predicate for this sink."""
        if self.predicate_code:
            return self.predicate_code

        # Generate based on category and language
        if language == "python":
            return self._to_python_sink()
        elif language == "java":
            return self._to_java_sink()
        elif language in ("javascript", "typescript"):
            return self._to_js_sink()
        elif language == "go":
            return self._to_go_sink()
        else:
            return self._to_generic_sink()

    def _to_python_sink(self) -> str:
        """Generate Python-specific sink predicate."""
        if self.category == "sql_query":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::moduleImport("sqlite3").getMember("Cursor").getMember("execute").getACall() and
    data = call.getArgument(0)
  )
  or
  exists(DataFlow::CallCfgNode call |
    call = API::moduleImport("sqlalchemy").getMember("engine").getMember("execute").getACall() and
    data = call.getArgument(0)
  )
}'''

        if self.category == "command_exec":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    (
      call = API::moduleImport("os").getMember("system").getACall() or
      call = API::moduleImport("subprocess").getMember("call").getACall() or
      call = API::moduleImport("subprocess").getMember("run").getACall() or
      call = API::moduleImport("subprocess").getMember("Popen").getACall()
    ) and
    data = call.getArgument(0)
  )
}'''

        if self.category == "http_response":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    (
      call = API::moduleImport("flask").getMember("render_template_string").getACall() or
      call = API::moduleImport("django").getMember("template").getMember("Template").getACall()
    ) and
    data = call.getArgument(0)
  )
}'''

        if self.category == "file_read" or self.category == "file_write":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    (
      call = API::moduleImport("os").getMember("path").getMember("join").getACall() or
      call = API::moduleImport("os").getMember("open").getACall() or
      call = API::moduleImport("builtins").getMember("open").getACall()
    ) and
    data = call.getArgument(0)
  )
}'''

        # Generic sink
        if self.vulnerable_functions:
            funcs = ', '.join(f'"{f}"' for f in self.vulnerable_functions)
            return f'''isSink(data: DataFlow::Node) {{
  exists(DataFlow::CallCfgNode call |
    call.getTarget().hasName([{funcs}]) and
    data = call.getArgument({self.argument_position or 0})
  )
}}'''

        return '''isSink(data: DataFlow::Node) {
  data instanceof SensitiveSink
}'''

    def _to_java_sink(self) -> str:
        """Generate Java-specific sink predicate."""
        if self.category == "sql_query":
            return '''isSink(data: DataFlow::Node) {
  exists(MethodCall mc |
    (
      mc.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") or
      mc.getMethod().hasName("executeQuery") or
      mc.getMethod().hasName("execute")
    ) and
    data = mc.getArgument(0)
  )
}'''

        if self.category == "command_exec":
            return '''isSink(data: DataFlow::Node) {
  exists(MethodCall mc |
    mc.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    mc.getMethod().hasName("exec") and
    data = mc.getArgument(0)
  )
}'''

        return '''isSink(data: DataFlow::Node) {
  data instanceof SensitiveSink
}'''

    def _to_js_sink(self) -> str:
        """Generate JavaScript-specific sink predicate."""
        if self.category == "sql_query":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::moduleImport("mysql").getMember("query").getACall() and
    data = call.getArgument(0)
  )
}'''

        if self.category == "command_exec":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    (
      call = API::moduleImport("child_process").getMember("exec").getACall() or
      call = API::moduleImport("child_process").getMember("spawn").getACall()
    ) and
    data = call.getArgument(0)
  )
}'''

        if self.category == "http_response":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    (
      call = API::moduleImport("express").getMember("response").getMember("send").getACall() or
      call = API::moduleImport("express").getMember("response").getMember("write").getACall()
    ) and
    data = call.getArgument(0)
  )
}'''

        return '''isSink(data: DataFlow::Node) {
  data instanceof SensitiveSink
}'''

    def _to_go_sink(self) -> str:
        """Generate Go-specific sink predicate."""
        if self.category == "sql_query":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::moduleImport("database/sql").getMember("DB").getMember("Query").getACall() and
    data = call.getArgument(0)
  )
}'''

        if self.category == "command_exec":
            return '''isSink(data: DataFlow::Node) {
  exists(DataFlow::CallCfgNode call |
    call = API::moduleImport("os/exec").getMember("Command").getACall() and
    data = call.getArgument(0)
  )
}'''

        return '''isSink(data: DataFlow::Node) {
  data instanceof SensitiveSink
}'''

    def _to_generic_sink(self) -> str:
        """Generate generic sink predicate."""
        return '''isSink(data: DataFlow::Node) {
  data instanceof SensitiveSink
}'''


@dataclass
class TaintTrackingConfig:
    """Configuration for CodeQL TaintTracking query."""

    # Query identification
    query_name: str
    query_id: str

    # Source and sink
    source: SourceDefinition
    sink: SinkDefinition

    # Language
    language: str = "python"

    # Additional options
    additional_steps: list[str] = field(default_factory=list)
    sanitizers: list[str] = field(default_factory=list)

    # Metadata
    description: str = ""
    severity: str = "medium"
    cwe: str | None = None
    tags: list[str] = field(default_factory=list)

    def to_query(self) -> str:
        """Generate complete CodeQL query."""
        return generate_taint_tracking_query(self)


@dataclass
class QueryTemplate:
    """Template for CodeQL query generation."""

    name: str
    category: VulnerabilityCategory
    language: str

    # Template patterns
    source_patterns: list[str] = field(default_factory=list)
    sink_patterns: list[str] = field(default_factory=list)
    sanitizer_patterns: list[str] = field(default_factory=list)

    # Metadata
    description: str = ""
    cwe_ids: list[str] = field(default_factory=list)


# Language-specific query header templates
QUERY_HEADERS = {
    "python": '''/**
 * @name {name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @tags {tags}
 * @id {query_id}
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs
import {{DataFlow::PathNode}} from DataFlowPrivate
''',
    "java": '''/**
 * @name {name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @tags {tags}
 * @id {query_id}
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph
''',
    "javascript": '''/**
 * @name {name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @tags {tags}
 * @id {query_id}
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import DataFlow::PathGraph
''',
    "go": '''/**
 * @name {name}
 * @description {description}
 * @kind path-problem
 * @problem.severity {severity}
 * @tags {tags}
 * @id {query_id}
 */

import go
import semmle.go.dataflow.TaintTracking
import DataFlow::PathGraph
''',
}


def generate_taint_tracking_query(config: TaintTrackingConfig) -> str:
    """
    Generate a complete CodeQL TaintTracking query.

    Args:
        config: TaintTracking configuration.

    Returns:
        Complete CodeQL query string.
    """
    # Get header for language
    header = QUERY_HEADERS.get(config.language, QUERY_HEADERS["python"])

    # Format header
    query = header.format(
        name=config.query_name,
        description=config.description or f"Taint tracking from {config.source.name} to {config.sink.name}",
        severity=config.severity,
        tags=" ".join(config.tags) if config.tags else "security",
        query_id=config.query_id,
    )

    # Add configuration class
    query += f'''
class {config.query_name.replace(" ", "").replace("-", "")}Config extends TaintTracking::Configuration {{
  {config.query_name.replace(" ", "").replace("-", "")}Config() {{ this = "{config.query_id}" }}

  override predicate isSource(DataFlow::Node source) {{
    {indent(config.source.to_codeql(config.language), 4)}
  }}

  override predicate isSink(DataFlow::Node sink) {{
    {indent(config.sink.to_codeql(config.language), 4)}
  }}
'''

    # Add sanitizers if defined
    if config.sanitizers:
        sanitizer_predicates = "\n    or\n    ".join(config.sanitizers)
        query += f'''
  override predicate isSanitizer(DataFlow::Node sanitizer) {{
    {sanitizer_predicates}
  }}
'''

    # Add additional taint steps if defined
    if config.additional_steps:
        steps = "\n    or\n    ".join(config.additional_steps)
        query += f'''
  override predicate isAdditionalTaintStep(DataFlow::Node pred, DataFlow::Node succ) {{
    {steps}
  }}
'''

    query += '''
}}

from DataFlow::PathNode source, DataFlow::PathNode sink
where {config_name}Config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Tainted data from $@ flows to here.",
  source.getNode(), "user input"
'''.format(config_name=config.query_name.replace(" ", "").replace("-", ""))

    return query


def indent(text: str, spaces: int) -> str:
    """Indent all lines of text by specified number of spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line if line.strip() else line for line in text.split("\n"))


class QueryGenerator:
    """
    Generates CodeQL dataflow queries from vulnerability candidates.

    Takes findings from Round 1 and generates customized TaintTracking queries
    that target the specific source and sink identified in the finding.
    """

    # Vulnerability type to category mapping
    VULN_TYPE_MAP: dict[str, VulnerabilityCategory] = {
        "sql": VulnerabilityCategory.SQL_INJECTION,
        "sqli": VulnerabilityCategory.SQL_INJECTION,
        "sql injection": VulnerabilityCategory.SQL_INJECTION,
        "xss": VulnerabilityCategory.XSS,
        "cross-site scripting": VulnerabilityCategory.XSS,
        "command": VulnerabilityCategory.COMMAND_INJECTION,
        "rce": VulnerabilityCategory.COMMAND_INJECTION,
        "os command": VulnerabilityCategory.COMMAND_INJECTION,
        "path traversal": VulnerabilityCategory.PATH_TRAVERSAL,
        "directory traversal": VulnerabilityCategory.PATH_TRAVERSAL,
        "lfi": VulnerabilityCategory.PATH_TRAVERSAL,
        "ssrf": VulnerabilityCategory.SSRF,
        "server-side request forgery": VulnerabilityCategory.SSRF,
        "redirect": VulnerabilityCategory.OPEN_REDIRECT,
        "ldap": VulnerabilityCategory.LDAP_INJECTION,
        "xpath": VulnerabilityCategory.XPATH_INJECTION,
        "ssti": VulnerabilityCategory.TEMPLATE_INJECTION,
        "template": VulnerabilityCategory.TEMPLATE_INJECTION,
        "deserialize": VulnerabilityCategory.DESERIALIZATION,
        "pickle": VulnerabilityCategory.DESERIALIZATION,
    }

    # Sink type to CodeQL category mapping
    SINK_TYPE_MAP: dict[str, str] = {
        "sql_query": "sql_query",
        "command_exec": "command_exec",
        "http_response": "http_response",
        "file_read": "file_read",
        "file_write": "file_write",
        "http_redirect": "http_redirect",
        "ldap_query": "ldap_query",
        "xpath_query": "xpath_query",
        "template_render": "template_render",
    }

    # Source type to CodeQL category mapping
    SOURCE_TYPE_MAP: dict[str, str] = {
        "http_param": "http_param",
        "http_header": "http_header",
        "http_body": "http_body",
        "http_cookie": "http_cookie",
        "file_input": "file_input",
        "user_input": "user_input",
        "env_var": "env_var",
        "command_arg": "command_arg",
        "rpc_param": "rpc_param",
    }

    def __init__(self, language: str = "python"):
        """
        Initialize the query generator.

        Args:
            language: Target language for query generation.
        """
        self.language = language
        self._query_counter = 0

    def generate_from_finding(
        self,
        finding: Finding,
        language: str | None = None,
    ) -> TaintTrackingConfig:
        """
        Generate a CodeQL query configuration from a vulnerability finding.

        Args:
            finding: The vulnerability finding from Round 1.
            language: Override language (defaults to instance language).

        Returns:
            TaintTrackingConfig ready for query generation.
        """
        lang = language or self.language

        # Infer vulnerability category
        category = self._infer_category(finding)

        # Generate source definition
        source = self._generate_source(finding, category, lang)

        # Generate sink definition
        sink = self._generate_sink(finding, category, lang)

        # Generate query ID
        self._query_counter += 1
        query_id = f"custom/dataflow/{category.value}_{self._query_counter}_{hashlib.md5(str(finding.location).encode()).hexdigest()[:8]}"

        # Create configuration
        config = TaintTrackingConfig(
            query_name=f"Custom {category.value.replace('_', ' ').title()} Analysis",
            query_id=query_id,
            source=source,
            sink=sink,
            language=lang,
            description=finding.title or f"Data flow analysis for {category.value}",
            severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            cwe=finding.cwe,
            tags=list(finding.tags) if finding.tags else ["security", "dataflow"],
        )

        # Add common sanitizers for this category
        config.sanitizers = self._get_sanitizers_for_category(category, lang)

        return config

    def _infer_category(self, finding: Finding) -> VulnerabilityCategory:
        """Infer vulnerability category from finding."""
        title = (finding.title or "").lower()

        # Check tags first
        if finding.tags:
            for tag in finding.tags:
                tag_lower = tag.lower()
                if tag_lower in self.VULN_TYPE_MAP:
                    return self.VULN_TYPE_MAP[tag_lower]

        # Check title
        for keyword, category in self.VULN_TYPE_MAP.items():
            if keyword in title:
                return category

        return VulnerabilityCategory.GENERIC

    def _generate_source(
        self,
        finding: Finding,
        category: VulnerabilityCategory,
        language: str,
    ) -> SourceDefinition:
        """Generate source definition from finding."""
        loc = finding.location

        # Determine source category based on finding
        source_category = "user_input"  # Default

        if category in (VulnerabilityCategory.SQL_INJECTION, VulnerabilityCategory.XSS,
                        VulnerabilityCategory.COMMAND_INJECTION):
            source_category = "http_param"
        elif category == VulnerabilityCategory.PATH_TRAVERSAL:
            source_category = "file_input"

        return SourceDefinition(
            name=f"source_{hashlib.md5(str(loc).encode()).hexdigest()[:8]}",
            category=source_category,
            file_path=loc.file,
            function_name=loc.function,
            line=loc.line,
            parameter_name=self._extract_parameter_name(finding),
        )

    def _generate_sink(
        self,
        finding: Finding,
        category: VulnerabilityCategory,
        language: str,
    ) -> SinkDefinition:
        """Generate sink definition from finding."""
        loc = finding.location

        # Map category to sink type
        sink_category = self.SINK_TYPE_MAP.get(
            category.value,
            category.value
        )

        return SinkDefinition(
            name=f"sink_{hashlib.md5(str(loc).encode()).hexdigest()[:8]}",
            category=sink_category,
            file_path=loc.file,
            function_name=loc.function,
            line=loc.line,
            vulnerable_functions=self._extract_vulnerable_functions(finding, category),
        )

    def _extract_parameter_name(self, finding: Finding) -> str | None:
        """Extract parameter name from finding context."""
        # Try to extract from snippet
        if finding.location.snippet:
            snippet = finding.location.snippet
            # Look for common patterns like request.args['param']
            import re
            match = re.search(r'\[["\'](\w+)["\']\]', snippet)
            if match:
                return match.group(1)
            match = re.search(r'\.get\(["\'](\w+)["\']', snippet)
            if match:
                return match.group(1)
        return None

    def _extract_vulnerable_functions(
        self,
        finding: Finding,
        category: VulnerabilityCategory,
    ) -> list[str]:
        """Extract vulnerable function names based on category."""
        # Common vulnerable functions by category
        vuln_funcs = {
            VulnerabilityCategory.SQL_INJECTION: ["execute", "query", "raw", "executemany"],
            VulnerabilityCategory.XSS: ["render_template_string", "innerHTML", "write"],
            VulnerabilityCategory.COMMAND_INJECTION: ["system", "popen", "subprocess", "exec"],
            VulnerabilityCategory.PATH_TRAVERSAL: ["open", "read", "write", "sendfile"],
        }

        funcs = vuln_funcs.get(category, [])

        # Add function from finding if available
        if finding.location.function:
            funcs.append(finding.location.function)

        return funcs

    def _get_sanitizers_for_category(
        self,
        category: VulnerabilityCategory,
        language: str,
    ) -> list[str]:
        """Get common sanitizers for a vulnerability category."""
        sanitizers = {
            VulnerabilityCategory.SQL_INJECTION: self._get_sql_sanitizers(language),
            VulnerabilityCategory.XSS: self._get_xss_sanitizers(language),
            VulnerabilityCategory.COMMAND_INJECTION: self._get_command_sanitizers(language),
            VulnerabilityCategory.PATH_TRAVERSAL: self._get_path_sanitizers(language),
        }

        return sanitizers.get(category, [])

    def _get_sql_sanitizers(self, language: str) -> list[str]:
        """Get SQL sanitizers for language."""
        if language == "python":
            return [
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('sqlite3').getMember('Cursor').getMember('execute').getACall())",
            ]
        return []

    def _get_xss_sanitizers(self, language: str) -> list[str]:
        """Get XSS sanitizers for language."""
        if language == "python":
            return [
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('bleach').getMember('clean').getACall())",
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('markupsafe').getMember('escape').getACall())",
            ]
        return []

    def _get_command_sanitizers(self, language: str) -> list[str]:
        """Get command injection sanitizers for language."""
        if language == "python":
            return [
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('shlex').getMember('quote').getACall())",
            ]
        return []

    def _get_path_sanitizers(self, language: str) -> list[str]:
        """Get path traversal sanitizers for language."""
        if language == "python":
            return [
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('os.path').getMember('realpath').getACall())",
                "exists(DataFlow::CallCfgNode call | call = API::moduleImport('os.path').getMember('basename').getACall())",
            ]
        return []

    def generate_query_file(
        self,
        config: TaintTrackingConfig,
        output_dir: Path,
    ) -> Path:
        """
        Generate a CodeQL query file.

        Args:
            config: TaintTracking configuration.
            output_dir: Directory to write the query file.

        Returns:
            Path to the generated query file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Generate query
        query = generate_taint_tracking_query(config)

        # Write to file
        query_file = output_dir / f"{config.query_id.replace('/', '_')}.ql"
        query_file.write_text(query)

        logger.info(f"Generated CodeQL query: {query_file}")
        return query_file
