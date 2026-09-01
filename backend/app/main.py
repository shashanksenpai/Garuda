from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import init_db
from .packet_simulator import simulator as packet_simulator
from .routers import actions, agents, events, incidents, live, logs, policy, status, topology

app = FastAPI(title="GARUDA", description="Agentic AI Cybersecurity Assistant", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    packet_simulator.start()


app.include_router(logs.router)
app.include_router(live.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(status.router)
app.include_router(topology.router)
app.include_router(actions.router)
app.include_router(policy.router)
app.include_router(agents.router)


@app.get("/")
def root():
    return {"name": "GARUDA", "status": "online"}
