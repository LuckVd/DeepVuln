"""
AST Context Extractor - Extract structured AST context for AI Agent.

Provides AST structure analysis to enhance AI reasoning by giving
the LLM precise information about code structure instead of just
raw source code.
"""

from dataclasses import dataclass, field
from typing import Any

from src.core.logger.logger import get_logger
from src.layers.l3_analysis.engines.ast_engine.graph.models import (
    ASTGraph,
    ASTNode,
)


@dataclass
class ASTContext:
    """
    Structured AST context for a code location.

    Attributes:
        code_snippet: The actual code snippet
        ast_structure: AST node structure (type, function, arguments)
        parent_context: Parent function/class context
        risk_analysis: Risk assessment (sink_type, confidence)
    """

    code_snippet: str
    ast_structure: dict[str, Any]
    parent_context: dict[str, Any] | None = None
    risk_analysis: dict[str, Any] | None = None

    def to_prompt_section(self) -> str:
        """Convert to a prompt section for LLM consumption."""
        lines = [
            "## AST Structure Analysis",
            "",
        ]

        # Code snippet
        lines.append(f"**Code Snippet:** `{self.code_snippet}`")
        lines.append("")

        # AST structure
        if self.ast_structure:
            lines.append("**AST Structure:**")
            for key, value in self.ast_structure.items():
                if isinstance(value, dict):
                    lines.append(f"- {key}:")
                    for k, v in value.items():
                        lines.append(f"  - {k}: {v}")
                elif isinstance(value, list):
                    lines.append(f"- {key}: {', '.join(str(v) for v in value)}")
                else:
                    lines.append(f"- {key}: {value}")
            lines.append("")

        # Parent context
        if self.parent_context:
            lines.append("**Parent Context:**")
            for key, value in self.parent_context.items():
                lines.append(f"- {key}: {value}")
            lines.append("")

        # Risk analysis
        if self.risk_analysis:
            lines.append("**Risk Assessment:**")
            for key, value in self.risk_analysis.items():
                lines.append(f"- {key}: {value}")
            lines.append("")

        return "\n".join(lines)


# Dangerous function patterns for risk assessment
DANGEROUS_FUNCTIONS = {
    # Code injection
    "eval": "code_injection",
    "exec": "code_injection",
    "compile": "code_injection",
    "__import__": "code_injection",
    # Command injection
    "system": "command_injection",
    "popen": "command_injection",
    "subprocess.call": "command_injection",
    "subprocess.Popen": "command_injection",
    "subprocess.run": "command_injection",
    "os.system": "command_injection",
    "os.popen": "command_injection",
    # SQL injection
    "execute": "sql_injection",
    "executemany": "sql_injection",
    "executescript": "sql_injection",
    "raw": "sql_injection",
    # Path traversal
    "open": "path_traversal",
    "read": "path_traversal",
    "write": "path_traversal",
    "send_file": "path_traversal",
    # Deserialization
    "pickle.load": "deserialization",
    "pickle.loads": "deserialization",
    "yaml.load": "deserialization",
    "marshal.load": "deserialization",
    # Weak crypto
    "md5": "weak_crypto",
    "sha1": "weak_crypto",
    "DES": "weak_crypto",
    "ARC4": "weak_crypto",
}


class ASTContextExtractor:
    """
    Extract structured AST context for AI Agent.

    Analyzes AST Graph to provide precise structural information
    about code at a specific location, enhancing LLM's understanding.
    """

    def __init__(self, ast_graph: ASTGraph | None = None) -> None:
        """
        Initialize the extractor.

        Args:
            ast_graph: Optional AST graph. If None, extraction will be limited.
        """
        self.ast_graph = ast_graph
        self.logger = get_logger(__name__)

    def extract_for_location(
        self,
        file_path: str,
        line: int,
        code_snippet: str | None = None,
    ) -> ASTContext:
        """
        Extract AST context for a specific code location.

        Args:
            file_path: Path to the source file
            line: Line number of interest
            code_snippet: Optional code snippet to include

        Returns:
            ASTContext with structured information
        """
        if not self.ast_graph:
            return self._create_minimal_context(code_snippet or "")

        # Find AST nodes at this location
        file_nodes = self.ast_graph.get_nodes_by_file(file_path)
        nearby_nodes = [
            n for n in file_nodes
            if abs(n.line - line) <= 5
        ]

        if not nearby_nodes:
            return self._create_minimal_context(code_snippet or "")

        # Find the most relevant node (closest to the line)
        target_node = min(nearby_nodes, key=lambda n: abs(n.line - line))

        # Extract AST structure
        ast_structure = self._extract_ast_structure(target_node)

        # Extract parent context
        parent_context = self._extract_parent_context(target_node)

        # Risk analysis
        risk_analysis = self._analyze_risk(target_node)

        return ASTContext(
            code_snippet=code_snippet or target_node.name,
            ast_structure=ast_structure,
            parent_context=parent_context,
            risk_analysis=risk_analysis,
        )

    def extract_for_sinks(
        self,
        sink_nodes: list[ASTNode],
    ) -> list[ASTContext]:
        """
        Extract AST context for multiple sink nodes.

        Args:
            sink_nodes: List of AST nodes representing sinks

        Returns:
            List of ASTContext objects
        """
        contexts = []

        for node in sink_nodes:
            ast_structure = self._extract_ast_structure(node)
            parent_context = self._extract_parent_context(node)
            risk_analysis = self._analyze_risk(node)

            context = ASTContext(
                code_snippet=node.name,
                ast_structure=ast_structure,
                parent_context=parent_context,
                risk_analysis=risk_analysis,
            )
            contexts.append(context)

        return contexts

    def _create_minimal_context(self, code_snippet: str) -> ASTContext:
        """Create a minimal context when AST graph is not available."""
        return ASTContext(
            code_snippet=code_snippet,
            ast_structure={"type": "unknown", "note": "AST graph not available"},
            parent_context=None,
            risk_analysis=None,
        )

    def _extract_ast_structure(self, node: ASTNode) -> dict[str, Any]:
        """Extract structured information from an AST node."""
        structure = {
            "type": node.type,
            "name": node.name,
            "line": node.line,
        }

        # Add children info if available
        if node.children:
            child_types = []
            for child_id in node.children:
                child = self.ast_graph.get_node(child_id) if self.ast_graph else None
                if child:
                    child_types.append(child.type)
            if child_types:
                structure["children_types"] = child_types[:5]  # Limit output

        # Add metadata if available
        if node.metadata:
            structure["metadata_keys"] = list(node.metadata.keys())[:3]

        return structure

    def _extract_parent_context(self, node: ASTNode) -> dict[str, Any] | None:
        """Extract parent function/class context."""
        if not self.ast_graph or not node.parent_id:
            return None

        parent = self.ast_graph.get_node(node.parent_id)
        if not parent:
            return None

        # Walk up to find function definition
        current = parent
        while current:
            if current.type in ("function_definition", "function_declaration",
                               "function", "method_definition"):
                return {
                    "type": current.type,
                    "name": current.name,
                    "line": current.line,
                }
            if not current.parent_id:
                break
            current = self.ast_graph.get_node(current.parent_id)

        # If no function found, return immediate parent
        return {
            "type": parent.type,
            "name": parent.name,
            "line": parent.line,
        }

    def _analyze_risk(self, node: ASTNode) -> dict[str, Any] | None:
        """Analyze risk based on node content."""
        node_name_lower = node.name.lower()

        # Check if it's a dangerous function
        for func_name, risk_type in DANGEROUS_FUNCTIONS.items():
            if func_name.lower() in node_name_lower:
                return {
                    "sink_type": risk_type,
                    "confidence": 0.9,
                    "dangerous_function": func_name,
                }

        # Check node type for potential issues
        if "call" in node.type.lower():
            return {
                "sink_type": "potential_sink",
                "confidence": 0.5,
                "note": "Function call - verify arguments",
            }

        return None

    def extract_for_code(
        self,
        code: str,
        language: str,
        file_path: str = "<unknown>",
    ) -> ASTContext:
        """
        Extract AST context by parsing code on-the-fly.

        Args:
            code: Source code to analyze
            language: Programming language
            file_path: Virtual file path

        Returns:
            ASTContext for the code
        """
        # Build AST graph from code
        from src.layers.l3_analysis.engines.ast_engine.graph.builder import (
            ASTGraphBuilder,
        )

        builder = ASTGraphBuilder()
        graph = builder.build_from_code(code, language, file_path)

        # Get the most interesting node (prefer call expressions)
        nodes = graph.get_nodes_by_type("call")
        if not nodes:
            nodes = graph.get_nodes_by_type("call_expression")
        if not nodes:
            nodes = list(graph.nodes.values())

        if nodes:
            # Use the first call node or first node
            target_node = nodes[0]

            ast_structure = self._extract_ast_structure_graph(target_node, graph)

            return ASTContext(
                code_snippet=code[:100] + "..." if len(code) > 100 else code,
                ast_structure=ast_structure,
                parent_context=None,
                risk_analysis=self._analyze_risk(target_node),
            )

        return self._create_minimal_context(code)

    def _extract_ast_structure_graph(
        self,
        node: ASTNode,
        graph: ASTGraph,
    ) -> dict[str, Any]:
        """Extract AST structure using graph methods."""
        structure = {
            "type": node.type,
            "name": node.name,
            "line": node.line,
        }

        # Add children info
        if node.children:
            children = [graph.get_node(cid) for cid in node.children]
            structure["children"] = [
                {"type": c.type, "name": c.name}
                for c in children
                if c is not None
            ][:5]

        return structure
