import logging

logger = logging.getLogger("netvisor.realtime")

_socket_server = None


def configure_socket_server(server) -> None:
    global _socket_server
    _socket_server = server


async def emit_event(event_name: str, payload: dict) -> None:
    if _socket_server is None:
        return

    try:
        await _socket_server.emit(event_name, payload)
    except Exception:
        logger.exception("Failed to emit realtime event %s", event_name)
