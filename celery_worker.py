#!/usr/bin/env python3
"""Celery worker entry point for DeepVuln."""
from src.web.core.celery_app import create_celery_app

app = create_celery_app()

if __name__ == '__main__':
    app.worker_main(['worker', '--loglevel=info', '--pool=solo', '-Q', 'scan'])
