"""Data models for attack surface detection."""

from enum import Enum

from pydantic import BaseModel, Field


class EntryPointType(str, Enum):
    """Types of attack entry points."""

    HTTP = "http"
    RPC = "rpc"
    GRPC = "grpc"
    MQ = "mq"  # Message Queue consumer
    CRON = "cron"  # Scheduled task
    FILE = "file"  # File input
    WEBSOCKET = "websocket"
    CLI = "cli"  # Command line interface


class HTTPMethod(str, Enum):
    """HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    ALL = "*"  # All methods


class EntryPoint(BaseModel):
    """Represents an attack entry point."""

    # Basic info
    type: EntryPointType = Field(..., description="Entry point type")
    method: HTTPMethod | None = Field(default=None, description="HTTP method if applicable")
    path: str = Field(..., description="Path or endpoint (e.g., /api/users/{id})")
    handler: str = Field(..., description="Handler function/method name")

    # Location
    file: str = Field(..., description="Source file path")
    line: int = Field(default=0, description="Line number in source file")

    # Security info
    auth_required: bool = Field(default=False, description="Whether authentication is required")
    params: list[str] = Field(default_factory=list, description="Parameter names")
    request_body_type: str | None = Field(default=None, description="Request body type/struct")

    # Metadata
    framework: str | None = Field(default=None, description="Framework name (gin, spring, flask)")
    middleware: list[str] = Field(default_factory=list, description="Middleware names")
    metadata: dict = Field(default_factory=dict, description="Additional metadata")

    def to_display(self) -> str:
        """Generate display string for this entry point."""
        if self.type == EntryPointType.HTTP and self.method:
            return f"{self.method.value} {self.path} -> {self.handler}"
        elif self.type == EntryPointType.RPC:
            return f"RPC {self.path} -> {self.handler}"
        elif self.type == EntryPointType.MQ:
            return f"MQ {self.path} -> {self.handler}"
        elif self.type == EntryPointType.CRON:
            return f"CRON {self.handler}"
        else:
            return f"{self.type.value} {self.path} -> {self.handler}"


class AttackSurfaceReport(BaseModel):
    """Attack surface analysis report."""

    # Source info
    source_path: str = Field(..., description="Analyzed source path")

    # Entry points
    entry_points: list[EntryPoint] = Field(default_factory=list, description="All entry points")

    # Statistics
    http_endpoints: int = Field(default=0, description="HTTP endpoint count")
    rpc_services: int = Field(default=0, description="RPC service count")
    grpc_services: int = Field(default=0, description="gRPC service count")
    mq_consumers: int = Field(default=0, description="Message queue consumer count")
    cron_jobs: int = Field(default=0, description="Cron job count")
    file_inputs: int = Field(default=0, description="File input count")
    websocket_endpoints: int = Field(default=0, description="WebSocket endpoint count")

    # Analysis metadata
    frameworks_detected: list[str] = Field(default_factory=list, description="Detected frameworks")
    files_scanned: int = Field(default=0, description="Number of files scanned")
    errors: list[str] = Field(default_factory=list, description="Analysis errors")

    def add_entry_point(self, entry: EntryPoint) -> None:
        """Add an entry point and update statistics."""
        self.entry_points.append(entry)

        # Update statistics
        if entry.type == EntryPointType.HTTP:
            self.http_endpoints += 1
        elif entry.type == EntryPointType.RPC:
            self.rpc_services += 1
        elif entry.type == EntryPointType.GRPC:
            self.grpc_services += 1
        elif entry.type == EntryPointType.MQ:
            self.mq_consumers += 1
        elif entry.type == EntryPointType.CRON:
            self.cron_jobs += 1
        elif entry.type == EntryPointType.FILE:
            self.file_inputs += 1
        elif entry.type == EntryPointType.WEBSOCKET:
            self.websocket_endpoints += 1

    @property
    def total_entry_points(self) -> int:
        """Total number of entry points."""
        return len(self.entry_points)

    def get_http_endpoints(self) -> list[EntryPoint]:
        """Get all HTTP entry points."""
        return [e for e in self.entry_points if e.type == EntryPointType.HTTP]

    def get_by_method(self, method: HTTPMethod) -> list[EntryPoint]:
        """Get HTTP entry points by method."""
        return [e for e in self.entry_points if e.method == method]

    def get_unauthenticated(self) -> list[EntryPoint]:
        """Get entry points without authentication."""
        return [e for e in self.entry_points if not e.auth_required]

    def get_summary(self) -> dict:
        """Get summary dictionary."""
        return {
            "source": self.source_path,
            "total_entry_points": self.total_entry_points,
            "http_endpoints": self.http_endpoints,
            "rpc_services": self.rpc_services,
            "grpc_services": self.grpc_services,
            "mq_consumers": self.mq_consumers,
            "cron_jobs": self.cron_jobs,
            "file_inputs": self.file_inputs,
            "websocket_endpoints": self.websocket_endpoints,
            "frameworks": self.frameworks_detected,
            "files_scanned": self.files_scanned,
            "unauthenticated": len(self.get_unauthenticated()),
        }
