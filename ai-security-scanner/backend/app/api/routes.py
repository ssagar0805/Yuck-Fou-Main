"""
API routes module.
Currently routes are defined directly in main.py for simplicity.
This file is reserved for route registration when the app grows.

Usage (in main.py):
    from app.api.routes import router
    app.include_router(router, prefix="/api")
"""

from fastapi import APIRouter

router = APIRouter()

# Routes will be migrated here in Phase 2 when the detection services are ready.
# For now, all routes live in app/main.py.
