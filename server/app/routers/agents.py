"""
/v1/agents — Agent registration and management.
"""

from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Agent
from app.schemas import AgentRegisterRequest, AgentResponse
from app.auth import verify_api_key, hash_api_key
import structlog

log = structlog.get_logger(__name__)
router = APIRouter()


@router.post(
    "/register",
    response_model=AgentResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new agent",
)
def register_agent(
    req: AgentRegisterRequest,
    db: Session = Depends(get_db),
) -> AgentResponse:
    """
    Called by the install script when deploying a new agent.
    Returns the stored agent record — the API key is only shown once.
    """
    # Check for duplicate
    existing = db.execute(
        select(Agent).where(Agent.id == req.agent_id)
    ).scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent {req.agent_id!r} already registered",
        )

    agent = Agent(
        id=req.agent_id,
        hostname=req.hostname,
        ip=req.ip or "",
        server_type=req.server_type,
        version=req.version or "",
        mode="shadow",  # all agents start in shadow mode for safety
        api_key_hash=hash_api_key(req.api_key),
    )
    db.add(agent)
    db.commit()
    db.refresh(agent)

    log.info("Agent registered", agent_id=req.agent_id, hostname=req.hostname)

    return AgentResponse(
        id=agent.id,
        hostname=agent.hostname,
        ip=agent.ip,
        server_type=agent.server_type,
        version=agent.version,
        mode=agent.mode,
        last_seen=None,
        created_at=agent.created_at.isoformat(),
    )


@router.get(
    "/",
    response_model=List[AgentResponse],
    summary="List all registered agents",
)
def list_agents(
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> List[AgentResponse]:
    agents = db.execute(
        select(Agent).order_by(Agent.created_at.desc())
    ).scalars().all()

    return [
        AgentResponse(
            id=a.id,
            hostname=a.hostname,
            ip=a.ip,
            server_type=a.server_type,
            version=a.version,
            mode=a.mode,
            last_seen=a.last_seen.isoformat() if a.last_seen else None,
            created_at=a.created_at.isoformat(),
        )
        for a in agents
    ]


@router.put(
    "/{agent_id}/mode",
    summary="Switch agent mode (enforce/shadow)",
)
def set_agent_mode(
    agent_id: str,
    mode: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    if mode not in ("enforce", "shadow"):
        raise HTTPException(status_code=400, detail="mode must be 'enforce' or 'shadow'")

    agent = db.execute(
        select(Agent).where(Agent.id == agent_id)
    ).scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    agent.mode = mode
    db.commit()
    log.info("Agent mode updated", agent_id=agent_id, mode=mode)
    return {"agent_id": agent_id, "mode": mode}


@router.post(
    "/{agent_id}/heartbeat",
    summary="Update agent last_seen timestamp",
)
def agent_heartbeat(
    agent_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> dict:
    agent = db.execute(
        select(Agent).where(Agent.id == agent_id)
    ).scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    agent.last_seen = datetime.now(timezone.utc)
    db.commit()
    return {"agent_id": agent_id, "last_seen": agent.last_seen.isoformat()}


@router.delete(
    "/{agent_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deregister and remove an agent",
)
def delete_agent(
    agent_id: str,
    db: Session = Depends(get_db),
    _: str = Depends(verify_api_key),
) -> None:
    agent = db.execute(
        select(Agent).where(Agent.id == agent_id)
    ).scalar_one_or_none()

    if not agent:
        raise HTTPException(status_code=404, detail=f"Agent {agent_id!r} not found")

    db.delete(agent)
    db.commit()
    log.info("Agent deregistered", agent_id=agent_id)
