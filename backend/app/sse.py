import asyncio
import json
from typing import Any


class Broadcaster:
    """Fan-out of pipeline updates to every connected SSE client."""

    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=100)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)

    async def publish(self, event_type: str, payload: dict[str, Any]):
        message = json.dumps({"type": event_type, "data": payload}, default=str)
        for q in list(self._subscribers):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass


broadcaster = Broadcaster()
