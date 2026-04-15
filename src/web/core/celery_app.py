"""Celery application configuration for background tasks.

P10-07: This module configures Celery for asynchronous task execution,
particularly for running security scans in the background.
"""

from typing import Optional

from celery import Celery
from pydantic_settings import BaseSettings


class CelerySettings(BaseSettings):
    """Celery configuration settings."""

    # Redis broker configuration
    redis_url: str = "redis://localhost:6379/0"
    redis_db: int = 0
    redis_password: Optional[str] = None

    # Celery configuration
    broker_url: str = "redis://localhost:6379/0"
    result_backend: str = "redis://localhost:6379/0"

    # Task configuration
    task_track_started: bool = True
    task_send_sent_event: bool = True
    task_acks_late: bool = True  # Acknowledge task after execution
    task_reject_on_worker_lost: bool = True  # Requeue if worker crashes

    # Task timeouts (in seconds)
    task_soft_time_limit: int = 82800  # 23 hours soft limit
    task_time_limit: int = 86400  # 24 hours hard limit

    # Task result expiration
    result_expires: int = 86400  # 24 hours
    result_extended: bool = True

    # Worker configuration
    worker_prefetch_multiplier: int = 1  # Disable prefetch for long tasks
    worker_max_tasks_per_child: int = 1  # One task per worker

    class Config:
        env_prefix = "CELERY_"


def get_celery_settings() -> CelerySettings:
    """Get Celery settings from environment.

    Returns:
        CelerySettings instance
    """
    try:
        return CelerySettings()
    except Exception:
        # Fallback to default settings
        return CelerySettings()


# Create Celery app
def create_celery_app() -> Celery:
    """Create and configure Celery application.

    Returns:
        Configured Celery application
    """
    settings = get_celery_settings()

    app = Celery(
        "deepvuln",
        broker=settings.broker_url,
        backend=None,  # 禁用 result backend - 扫描结果直接存数据库
        include=[
            "src.web.tasks.scan_tasks",
        ],
    )

    # Configure Celery
    app.conf.update(
        # Task settings
        task_track_started=settings.task_track_started,
        task_send_sent_event=settings.task_send_sent_event,
        task_acks_late=settings.task_acks_late,
        task_reject_on_worker_lost=settings.task_reject_on_worker_lost,
        # Time limits
        task_soft_time_limit=settings.task_soft_time_limit,
        task_time_limit=settings.task_time_limit,
        # Result backend
        result_expires=settings.result_expires,
        result_extended=settings.result_extended,
        # Worker settings
        worker_prefetch_multiplier=settings.worker_prefetch_multiplier,
        worker_max_tasks_per_child=settings.worker_max_tasks_per_child,
        # Task routing (optional)
        task_routes={
            "execute_scan_task": {"queue": "scan"},
            "check_scan_progress": {"queue": "scan"},
        },
        # Default queue for tasks without explicit routing
        task_default_queue="scan",
        # Task serialization
        task_serializer="json",
        task_accept_content=["json"],
        result_serializer="json",
        result_accept_content=["json"],
    )

    return app


# Lazy-loaded Celery app
_celery_app: Optional[Celery] = None


def get_celery_app() -> Celery:
    """Get or create Celery application (lazy initialization).

    Returns:
        Celery application instance
    """
    global _celery_app
    if _celery_app is None:
        _celery_app = create_celery_app()
    return _celery_app
