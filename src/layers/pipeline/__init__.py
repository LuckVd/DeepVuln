"""Shared scan pipeline orchestration layer.

Provides a thin, domain-agnostic pipeline that executes scan phases in order
with progress broadcasting and checkpoint-based resume. CLI and Web both build
a ScanPipeline over the SAME phase runners (which reuse the engines /
adjudication / verification code in ``src/layers/l3_analysis``) and differ only
in the ProgressSink / CheckpointSink adapters they inject — eliminating the
former CLI/Web orchestration duplication.

Layering: this module lives under ``src/layers`` and depends only on core +
its own submodules. Web/CLI adapters implement the ProgressSink / CheckpointSink
protocols and are injected at construction time.
"""

from src.layers.pipeline.checkpoint import CheckpointSink
from src.layers.pipeline.context import ScanContext
from src.layers.pipeline.phases import PhaseRunner, PhaseSpec, ScanPhase
from src.layers.pipeline.progress import ProgressSink
from src.layers.pipeline.scan_pipeline import ScanPipeline

__all__ = [
    "CheckpointSink",
    "ScanContext",
    "ScanPhase",
    "PhaseSpec",
    "PhaseRunner",
    "ProgressSink",
    "ScanPipeline",
]
