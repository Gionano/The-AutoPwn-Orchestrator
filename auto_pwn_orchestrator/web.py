from __future__ import annotations

import json
import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .config import Config

logger = logging.getLogger(__name__)

app = FastAPI()
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")
config: Config | None = None


def start_web_server(cfg: Config):
    global config
    config = cfg
    import uvicorn

    logger.info(f"Starting web dashboard at http://{cfg.web.host}:{cfg.web.port}")
    uvicorn.run(app, host=cfg.web.host, port=cfg.web.port, log_level="info")


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    if not config:
        return "Config not loaded"
    
    report_path = config.output.directory / config.output.report_file
    inventory_path = config.output.directory / config.output.inventory_file
    
    report_data = {}
    inventory_data = {}

    if report_path.exists():
        report_data = json.loads(report_path.read_text())
    
    if inventory_path.exists():
        inventory_data = json.loads(inventory_path.read_text())

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "report": report_data,
            "inventory": inventory_data,
            "config": config,
        },
    )
