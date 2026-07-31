import uvicorn

from recallops.api import create_app

app = create_app()


def run() -> None:
    uvicorn.run("recallops.main:app", host="0.0.0.0", port=8080)
