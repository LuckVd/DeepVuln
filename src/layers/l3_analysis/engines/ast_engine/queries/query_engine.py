"""Query Engine - Executes tree-sitter queries on AST."""

import yaml
from pathlib import Path
from typing import Any

from src.core.logger.logger import get_logger


class QueryEngine:
    """
    Engine for executing tree-sitter queries on AST trees.

    Provides a high-level API for running queries and extracting
    structured results from AST nodes.
    """

    def __init__(self) -> None:
        """Initialize the QueryEngine."""
        self.logger = get_logger(__name__)

    def execute_query(
        self,
        query_text: str,
        code: str,
        language: str,
        language_obj: Any = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a tree-sitter query on source code.

        Args:
            query_text: Tree-sitter query string.
            code: Source code to query.
            language: Programming language name.
            language_obj: Optional pre-loaded Language object.

        Returns:
            List of query result dictionaries with capture information.
        """
        try:
            from tree_sitter import Language, Parser, Query, QueryCursor

        except ImportError:
            self.logger.error("tree-sitter not available")
            return []

        # Import TreeSitterManager to get language if not provided
        if language_obj is None:
            from src.layers.l3_analysis.engines.ast_engine.parser.tree_sitter_manager import TreeSitterManager

            manager = TreeSitterManager()
            language_obj = manager.get_language(language)

        if language_obj is None:
            self.logger.warning(f"Language not available: {language}")
            return []

        # Parse the code
        try:
            parser = Parser(language_obj)
            tree = parser.parse(bytes(code, "utf-8"))
        except Exception as e:
            self.logger.error(f"Failed to parse code: {e}")
            return []

        # Execute the query
        return self._execute_query_on_tree(query_text, language_obj, tree)

    def _execute_query_on_tree(
        self,
        query_text: str,
        language_obj: Any,
        tree: Any,
    ) -> list[dict[str, Any]]:
        """Execute a query on an existing AST tree.

        Args:
            query_text: Tree-sitter query string.
            language_obj: Language object for the tree.
            tree: Parsed AST tree.

        Returns:
            List of query result dictionaries.
        """
        try:
            from tree_sitter import Query, QueryCursor

        except ImportError:
            self.logger.error("tree-sitter not available")
            return []

        try:
            query = Query(language_obj, query_text)
        except Exception as e:
            self.logger.error(f"Failed to create query: {e}")
            return []

        results = []
        try:
            cursor = QueryCursor(query)
            matches = cursor.matches(tree.root_node)

            for _pattern_idx, captures in matches:
                # Process each capture
                for capture_name, nodes in captures.items():
                    for node in nodes:
                        results.append({
                            "capture": capture_name,
                            "type": node.type,
                            "text": node.text.decode("utf-8"),
                            "line": node.start_point[0] + 1,
                            "column": node.start_point[1] + 1,
                            "start_byte": node.start_byte,
                            "end_byte": node.end_byte,
                        })

        except Exception as e:
            self.logger.error(f"Failed to execute query: {e}")

        return results

    def execute_query_on_tree(
        self,
        query_text: str,
        tree: Any,
        language_obj: Any,
    ) -> list[dict[str, Any]]:
        """Execute a query on an existing AST tree.

        Args:
            query_text: Tree-sitter query string.
            tree: Parsed AST tree.
            language_obj: Language object for the tree.

        Returns:
            List of query result dictionaries.
        """
        return self._execute_query_on_tree(query_text, language_obj, tree)

    def load_yaml_rule(self, rule_path: str | Path) -> dict[str, Any]:
        """Load a rule definition from a YAML file.

        Args:
            rule_path: Path to the YAML rule file.

        Returns:
            Dictionary containing rule definition.
        """
        rule_path = Path(rule_path)

        if not rule_path.exists():
            raise FileNotFoundError(f"Rule file not found: {rule_path}")

        with open(rule_path, encoding="utf-8") as f:
            rule = yaml.safe_load(f)

        return rule

    def load_yaml_rules_from_dir(
        self,
        rules_dir: str | Path,
    ) -> list[dict[str, Any]]:
        """Load all YAML rules from a directory.

        Args:
            rules_dir: Path to the rules directory.

        Returns:
            List of rule dictionaries.
        """
        rules_dir = Path(rules_dir)

        if not rules_dir.is_dir():
            self.logger.warning(f"Rules directory not found: {rules_dir}")
            return []

        rules = []

        for yaml_file in rules_dir.rglob("*.yaml"):
            try:
                rule = self.load_yaml_rule(yaml_file)
                rules.append(rule)
            except Exception as e:
                self.logger.debug(f"Failed to load rule {yaml_file}: {e}")

        for yaml_file in rules_dir.rglob("*.yml"):
            try:
                rule = self.load_yaml_rule(yaml_file)
                rules.append(rule)
            except Exception as e:
                self.logger.debug(f"Failed to load rule {yaml_file}: {e}")

        return rules
