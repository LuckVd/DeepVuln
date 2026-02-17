"""Attack surface detection module."""

from src.layers.l1_intelligence.attack_surface.ast import (
    ASTDetector,
    GoASTDetector,
    JavaASTDetector,
    PythonASTDetector,
)
from src.layers.l1_intelligence.attack_surface.detector import AttackSurfaceDetector
from src.layers.l1_intelligence.attack_surface.models import (
    AttackSurfaceReport,
    EntryPoint,
    EntryPointType,
    HTTPMethod,
)
from src.layers.l1_intelligence.attack_surface.mq_detector import (
    CronDetector,
    KafkaDetector,
    RabbitMQDetector,
    RedisDetector,
)
from src.layers.l1_intelligence.attack_surface.rpc_detector import (
    DubboDetector,
    GrpcDetector,
    ThriftDetector,
)

__all__ = [
    # Main detector
    "AttackSurfaceDetector",
    # Models
    "AttackSurfaceReport",
    "EntryPoint",
    "EntryPointType",
    "HTTPMethod",
    # AST detectors
    "ASTDetector",
    "JavaASTDetector",
    "PythonASTDetector",
    "GoASTDetector",
    # Regex detectors
    "DubboDetector",
    "GrpcDetector",
    "ThriftDetector",
    "KafkaDetector",
    "RabbitMQDetector",
    "RedisDetector",
    "CronDetector",
]
