"""Java AST-based attack surface detector using Tree-sitter."""

from pathlib import Path
from typing import Any

import tree_sitter_java as tsjava

from src.core.logger.logger import get_logger
from src.layers.l1_intelligence.attack_surface.ast.base import (
    ASTDetector,
    register_ast_detector,
)
from src.layers.l1_intelligence.attack_surface.models import (
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)


@register_ast_detector
class JavaASTDetector(ASTDetector):
    """AST-based detector for Java frameworks (Spring, Dubbo, etc.).

    Uses Tree-sitter to parse Java source code and extract entry points
    from annotations like @DubboService, @GetMapping, @KafkaListener, etc.
    """

    language_module = tsjava
    language_name = "java"
    file_extensions = [".java"]

    def __init__(self) -> None:
        """Initialize the Java AST detector."""
        super().__init__()
        self.logger = get_logger(__name__)

    def _extract_entry_points(
        self, root: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract entry points from Java AST.

        Args:
            root: Root node of the AST.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of detected entry points.
        """
        entry_points: list[EntryPoint] = []

        # Extract class-level prefix for Spring controllers
        class_prefix = self._extract_class_prefix(root, content)

        # Walk the AST and find class declarations
        self._walk_and_extract(root, content, file_path, entry_points, class_prefix)

        return entry_points

    def _walk_and_extract(
        self,
        node: Any,
        content: str,
        file_path: Path,
        entry_points: list[EntryPoint],
        class_prefix: str,
    ) -> None:
        """Walk the AST and extract entry points.

        Args:
            node: Current AST node.
            content: Original source code content.
            file_path: Path to the source file.
            entry_points: List to append found entry points.
            class_prefix: Class-level path prefix.
        """
        if node.type == "class_declaration":
            # Extract Dubbo services from class
            dubbo_entries = self._extract_dubbo_from_class(node, content, file_path)
            entry_points.extend(dubbo_entries)

            # Extract class-level @RequestMapping for Spring
            prefix_from_class = self._get_class_mapping_prefix(node, content)
            effective_prefix = prefix_from_class if prefix_from_class else class_prefix

            # Process method declarations within the class
            for child in node.children:
                if child.type == "class_body":
                    for member in child.children:
                        if member.type == "method_declaration":
                            # Extract Spring HTTP endpoints
                            http_entries = self._extract_spring_from_method(
                                member, content, file_path, effective_prefix
                            )
                            entry_points.extend(http_entries)

                            # Extract Kafka listeners
                            kafka_entries = self._extract_kafka_from_method(
                                member, content, file_path
                            )
                            entry_points.extend(kafka_entries)

                            # Extract RabbitMQ listeners
                            rabbit_entries = self._extract_rabbit_from_method(
                                member, content, file_path
                            )
                            entry_points.extend(rabbit_entries)

                            # Extract scheduled tasks
                            cron_entries = self._extract_scheduled_from_method(
                                member, content, file_path
                            )
                            entry_points.extend(cron_entries)

        # Recursively walk children
        for child in node.children:
            self._walk_and_extract(child, content, file_path, entry_points, class_prefix)

    def _extract_class_prefix(self, root: Any, content: str) -> str:
        """Extract class-level @RequestMapping prefix.

        Args:
            root: Root node of the AST.
            content: Original source code content.

        Returns:
            Class-level path prefix or empty string.
        """
        # Walk to find class declarations
        for child in root.children:
            if child.type == "class_declaration":
                return self._get_class_mapping_prefix(child, content)
        return ""

    def _get_class_mapping_prefix(self, class_node: Any, content: str) -> str:
        """Get the @RequestMapping prefix from a class declaration.

        Args:
            class_node: Class declaration node.
            content: Original source code content.

        Returns:
            Path prefix or empty string.
        """
        for child in class_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name == "RequestMapping":
                        path = self._get_annotation_string_arg(mod, content)
                        if path:
                            return path
        return ""

    def _extract_dubbo_from_class(
        self, class_node: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract Dubbo RPC services from a class declaration.

        Args:
            class_node: Class declaration node.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of RPC entry points.
        """
        entry_points: list[EntryPoint] = []

        for child in class_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name in ("DubboService", "Service"):
                        # Get class name
                        class_name = self._get_class_name(class_node, content)
                        if class_name:
                            entry = EntryPoint(
                                type=EntryPointType.RPC,
                                path=class_name,
                                handler=class_name,
                                file=str(file_path),
                                line=self._get_line_number(class_node),
                                framework="dubbo",
                                metadata={"protocol": "dubbo"},
                            )
                            entry_points.append(entry)
                        break

        return entry_points

    def _extract_spring_from_method(
        self, method_node: Any, content: str, file_path: Path, class_prefix: str
    ) -> list[EntryPoint]:
        """Extract Spring HTTP endpoints from a method declaration.

        Args:
            method_node: Method declaration node.
            content: Original source code content.
            file_path: Path to the source file.
            class_prefix: Class-level path prefix.

        Returns:
            List of HTTP entry points.
        """
        entry_points: list[EntryPoint] = []

        for child in method_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name and ann_name.endswith("Mapping"):
                        method = self._get_http_method(ann_name)
                        path = self._get_annotation_string_arg(mod, content)

                        if path:
                            full_path = (class_prefix + path) if class_prefix else path
                            method_name = self._get_method_name(method_node, content)

                            entry = EntryPoint(
                                type=EntryPointType.HTTP,
                                method=method,
                                path=full_path,
                                handler=method_name or "unknown",
                                file=str(file_path),
                                line=self._get_line_number(method_node),
                                framework="spring",
                            )
                            entry_points.append(entry)

        return entry_points

    def _extract_kafka_from_method(
        self, method_node: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract Kafka listener methods.

        Args:
            method_node: Method declaration node.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of MQ entry points.
        """
        entry_points: list[EntryPoint] = []

        for child in method_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name == "KafkaListener":
                        topic = self._get_annotation_named_arg(mod, content, "topics")
                        if topic:
                            method_name = self._get_method_name(method_node, content)
                            entry = EntryPoint(
                                type=EntryPointType.MQ,
                                path=topic,
                                handler=method_name or "unknown",
                                file=str(file_path),
                                line=self._get_line_number(method_node),
                                framework="kafka",
                                metadata={"protocol": "kafka"},
                            )
                            entry_points.append(entry)

        return entry_points

    def _extract_rabbit_from_method(
        self, method_node: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract RabbitMQ listener methods.

        Args:
            method_node: Method declaration node.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of MQ entry points.
        """
        entry_points: list[EntryPoint] = []

        for child in method_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name == "RabbitListener":
                        queue = self._get_annotation_named_arg(mod, content, "queues")
                        if queue:
                            method_name = self._get_method_name(method_node, content)
                            entry = EntryPoint(
                                type=EntryPointType.MQ,
                                path=queue,
                                handler=method_name or "unknown",
                                file=str(file_path),
                                line=self._get_line_number(method_node),
                                framework="rabbitmq",
                                metadata={"protocol": "amqp"},
                            )
                            entry_points.append(entry)

        return entry_points

    def _extract_scheduled_from_method(
        self, method_node: Any, content: str, file_path: Path
    ) -> list[EntryPoint]:
        """Extract scheduled task methods.

        Args:
            method_node: Method declaration node.
            content: Original source code content.
            file_path: Path to the source file.

        Returns:
            List of CRON entry points.
        """
        entry_points: list[EntryPoint] = []

        for child in method_node.children:
            if child.type == "modifiers":
                for mod in child.children:
                    ann_name = self._get_annotation_name(mod, content)
                    if ann_name == "Scheduled":
                        # Get schedule info from cron or fixedRate
                        cron = self._get_annotation_named_arg(mod, content, "cron")
                        fixed_rate = self._get_annotation_named_arg(mod, content, "fixedRate")
                        schedule_info = cron or fixed_rate or "@Scheduled"

                        method_name = self._get_method_name(method_node, content)
                        entry = EntryPoint(
                            type=EntryPointType.CRON,
                            path=schedule_info,
                            handler=method_name or "unknown",
                            file=str(file_path),
                            line=self._get_line_number(method_node),
                            framework="spring",
                            metadata={"schedule": schedule_info},
                        )
                        entry_points.append(entry)

        return entry_points

    def _get_annotation_name(self, node: Any, content: str) -> str | None:
        """Get the name of an annotation node.

        Args:
            node: Annotation node (annotation or marker_annotation).
            content: Original source code content.

        Returns:
            Annotation name or None.
        """
        if node.type not in ("annotation", "marker_annotation"):
            return None

        for child in node.children:
            if child.type in ("identifier", "type_identifier"):
                return self._get_text(child, content)
            elif child.type == "scoped_type_identifier":
                # Handle @org.apache.dubbo.config.annotation.Service
                return self._get_text(child, content)

        return None

    def _get_annotation_string_arg(self, node: Any, content: str) -> str | None:
        """Get the string argument from an annotation.

        Args:
            node: Annotation node.
            content: Original source code content.

        Returns:
            String argument value or None.
        """
        if node.type not in ("annotation", "marker_annotation"):
            return None

        for child in node.children:
            # Handle both argument_list and annotation_argument_list
            if child.type in ("argument_list", "annotation_argument_list"):
                for arg in child.children:
                    if arg.type == "string_literal":
                        text = self._get_text(arg, content)
                        # Remove quotes
                        return text.strip('"\'')
                    elif arg.type == "element_value_pair":
                        # Handle value = "/path"
                        for pair_child in arg.children:
                            if pair_child.type == "identifier":
                                key = self._get_text(pair_child, content)
                                if key in ("value", "path"):
                                    # Find the value
                                    for pc in arg.children:
                                        if pc.type == "string_literal":
                                            return self._get_text(pc, content).strip('"\'')

        return None

    def _get_annotation_named_arg(
        self, node: Any, content: str, arg_name: str
    ) -> str | None:
        """Get a named argument value from an annotation.

        Args:
            node: Annotation node.
            content: Original source code content.
            arg_name: Argument name to find.

        Returns:
            Argument value or None.
        """
        if node.type not in ("annotation", "marker_annotation"):
            return None

        for child in node.children:
            # Handle both argument_list and annotation_argument_list
            if child.type in ("argument_list", "annotation_argument_list"):
                for arg in child.children:
                    if arg.type == "element_value_pair":
                        key = None
                        value = None
                        for pair_child in arg.children:
                            if pair_child.type == "identifier":
                                key = self._get_text(pair_child, content)
                            elif pair_child.type == "string_literal":
                                value = self._get_text(pair_child, content).strip('"\'')

                        if key == arg_name and value:
                            return value

        return None

    def _get_class_name(self, class_node: Any, content: str) -> str | None:
        """Get the name of a class declaration.

        Args:
            class_node: Class declaration node.
            content: Original source code content.

        Returns:
            Class name or None.
        """
        for child in class_node.children:
            if child.type == "identifier":
                return self._get_text(child, content)
        return None

    def _get_method_name(self, method_node: Any, content: str) -> str | None:
        """Get the name of a method declaration.

        Args:
            method_node: Method declaration node.
            content: Original source code content.

        Returns:
            Method name or None.
        """
        for child in method_node.children:
            if child.type == "identifier":
                return self._get_text(child, content)
        return None

    def _get_http_method(self, annotation_name: str) -> HTTPMethod:
        """Get HTTP method from annotation name.

        Args:
            annotation_name: Annotation name (e.g., "GetMapping").

        Returns:
            HTTP method enum value.
        """
        mapping = {
            "GetMapping": HTTPMethod.GET,
            "PostMapping": HTTPMethod.POST,
            "PutMapping": HTTPMethod.PUT,
            "DeleteMapping": HTTPMethod.DELETE,
            "PatchMapping": HTTPMethod.PATCH,
            "RequestMapping": HTTPMethod.ALL,
        }
        return mapping.get(annotation_name, HTTPMethod.ALL)
