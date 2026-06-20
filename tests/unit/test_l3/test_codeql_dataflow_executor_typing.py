"""Phase 18/P4-C2: CodeQLDataflowExecutor taint source/sink typing.

``_create_taint_source`` / ``_create_taint_sink`` accept a ``PathLocation``
(the real type of ``parsed.source`` / ``parsed.sink`` produced by the SARIF
parser), not ``ParsedDataflowPath``. The misleading signature and the
``hasattr(path_loc, 'to_code_location')`` guard have been removed; these tests
lock the PathLocation contract in place.
"""

from unittest.mock import MagicMock

from src.layers.l3_analysis.codeql.executor import CodeQLDataflowExecutor
from src.layers.l3_analysis.codeql.sarif_parser import PathLocation


def _executor() -> CodeQLDataflowExecutor:
    """Build an executor bypassing __init__ — helpers only need the location."""
    return CodeQLDataflowExecutor.__new__(CodeQLDataflowExecutor)


def _config() -> MagicMock:
    config = MagicMock()
    config.source.category = "http_param"
    config.sink.category = "sql_query"
    config.query_id = "q1234567890"
    return config


def test_create_taint_source_with_path_location():
    source = _executor()._create_taint_source(
        PathLocation(
            file_path="a.py",
            line=5,
            variable_name="user_input",
            function_name="handler",
        ),
        _config(),
    )
    assert source.variable_name == "user_input"
    assert source.location.file == "a.py"
    assert source.location.function == "handler"


def test_create_taint_sink_with_path_location():
    sink = _executor()._create_taint_sink(
        PathLocation(file_path="a.py", line=9, function_name="execute_query"),
        _config(),
    )
    assert sink.function_name == "execute_query"
    assert sink.location.line == 9


def test_create_taint_source_handles_none():
    """A missing location degrades to an empty CodeLocation, no AttributeError."""
    source = _executor()._create_taint_source(None, _config())
    assert source.variable_name is None
    assert source.location.file == ""
