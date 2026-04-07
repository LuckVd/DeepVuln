"""CPG path providers for different languages."""

from src.layers.l3_analysis.engines.ast_engine.cpg.providers.js_provider import (
    JSCPGProvider,
)
from src.layers.l3_analysis.engines.ast_engine.cpg.providers.python_provider import (
    PythonCPGProvider,
)

__all__ = ["PythonCPGProvider", "JSCPGProvider"]
