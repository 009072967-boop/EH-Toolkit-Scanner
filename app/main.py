from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import Base, engine
from app import models  # noqa: F401 - ensures models are registered before create_all
from app.routers import audit, dashboard, scans, targets

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Defensive Pentest Scanner",
    description="Self-hosted scanning for infrastructure you own or are authorized to test.",
)

static_dir = Path(__file__).parent / "static"
static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

app.include_router(dashboard.router)
app.include_router(targets.router)
app.include_router(scans.router)
app.include_router(audit.router)
