from botocore.config import Config


class DependencyUnavailable(RuntimeError):
    def __init__(self, dependency: str) -> None:
        super().__init__(f"dependency unavailable: {dependency}")
        self.dependency = dependency


def aws_client_config(connect_timeout: float, read_timeout: float, attempts: int) -> Config:
    return Config(
        connect_timeout=connect_timeout,
        read_timeout=read_timeout,
        retries={"mode": "standard", "total_max_attempts": attempts},
        tcp_keepalive=True,
    )
