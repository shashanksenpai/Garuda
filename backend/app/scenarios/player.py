import asyncio

from ..database import SessionLocal
from ..pipeline import process_raw_event
from ..sse import broadcaster
from .definitions import SCENARIOS


class ScenarioPlayer:
    def __init__(self):
        self._task: asyncio.Task | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def start(self, scenario_name: str, speed: float = 1.0):
        if scenario_name not in SCENARIOS:
            raise ValueError(f"Unknown scenario: {scenario_name}")
        if self.running:
            self.stop()
        self._task = asyncio.create_task(self._run(scenario_name, speed))

    def stop(self):
        if self._task is not None:
            self._task.cancel()
            self._task = None

    async def _run(self, scenario_name: str, speed: float):
        events = SCENARIOS[scenario_name]()
        events = sorted(events, key=lambda pair: pair[0])
        start = 0.0
        try:
            await broadcaster.publish("scenario_started", {"scenario": scenario_name})
            for delay, raw in events:
                wait = max(0.0, (delay - start) / max(speed, 0.01))
                await asyncio.sleep(wait)
                start = delay
                db = SessionLocal()
                try:
                    messages = process_raw_event(db, "scenario", raw)
                    for m in messages:
                        await broadcaster.publish(m["type"], m["data"])
                finally:
                    db.close()
            await broadcaster.publish("scenario_finished", {"scenario": scenario_name})
        except asyncio.CancelledError:
            pass


player = ScenarioPlayer()
