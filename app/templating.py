from pathlib import Path

from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _severity_rank(severity) -> int:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    value = severity.value if hasattr(severity, "value") else str(severity)
    return order.get(value, 5)


templates.env.filters["severity_rank"] = _severity_rank
