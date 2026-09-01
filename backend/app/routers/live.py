import asyncio

from fastapi import APIRouter
from sse_starlette.sse import EventSourceResponse

from .. import schemas
from ..scenarios.definitions import SCENARIOS
from ..scenarios.player import player
from ..sse import broadcaster

router = APIRouter(prefix="/api", tags=["live"])


@router.get("/scenarios")
async def list_scenarios():
    return {"scenarios": list(SCENARIOS.keys())}


@router.post("/logs/start-live")
async def start_live(payload: schemas.StartLiveRequest):
    """Starts Sample Mode (scenario replay) or, in principle, a live sensor feed.
    For this prototype only scenario replay is implemented; a real Zeek/Suricata
    tailer would call the same `process_raw_event` pipeline from its own reader."""
    scenario = payload.scenario or "multi_stage_attack"
    player.start(scenario, payload.speed)
    return {"status": "started", "scenario": scenario, "speed": payload.speed}


@router.post("/logs/stop-live")
async def stop_live():
    player.stop()
    return {"status": "stopped"}


@router.get("/logs/status")
async def live_status():
    return {"running": player.running}


@router.get("/live/stream")
async def stream():
    queue = broadcaster.subscribe()

    async def event_generator():
        try:
            while True:
                message = await queue.get()
                yield message
        except asyncio.CancelledError:
            pass
        finally:
            broadcaster.unsubscribe(queue)

    return EventSourceResponse(event_generator())
