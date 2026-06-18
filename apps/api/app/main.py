from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.settings import get_settings

settings = get_settings()

app = FastAPI(
    title="Gatehouse API",
    version="0.2.0",
    description="CI/CD pipeline security review for GitHub Actions, GitLab CI, and Jenkins.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
app.include_router(router)
