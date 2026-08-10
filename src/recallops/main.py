import uvicorn

from recallops.api import create_app

app = create_app()


def run() -> None:
    # Container ingress is constrained by its network/security group, so the
    # application must listen on every container interface.
    uvicorn.run("recallops.main:app", host="0.0.0.0", port=8080)  # nosec B104
