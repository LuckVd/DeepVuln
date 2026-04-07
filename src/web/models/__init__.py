"""Web service models."""

from src.web.models.database import Base, get_db, init_db, close_db
from src.web.models.project import Project
from src.web.models.scan import Scan, ScanPhase, ScanEvent
from src.web.models.finding import Finding
from src.web.models.checkpoint import ScanFile, ApiKey
from src.web.models.schemas import *

__all__ = [
    # Database
    "Base",
    "get_db",
    "init_db",
    "close_db",
    # ORM Models
    "Project",
    "Scan",
    "ScanPhase",
    "ScanEvent",
    "Finding",
    "ScanFile",
    "ApiKey",
    # Schemas (Pydantic)
    "ProjectCreate",
    "ProjectUpdate",
    "ProjectResponse",
    "ProjectListResponse",
    "ScanCreate",
    "ScanResponse",
    "ScanListResponse",
    "ScanProgressResponse",
    "AgentConversationResponse",
    "CurrentFileResponse",
    "FindingCreate",
    "FindingUpdate",
    "FindingResponse",
    "FindingListResponse",
    "ScanEventResponse",
    "ScanEventListResponse",
    "WebSocketEvent",
    # Enums
    "ScanStatus",
    "ScanType",
    "SeverityLevel",
    "FindingStatus",
    "PhaseName",
]
