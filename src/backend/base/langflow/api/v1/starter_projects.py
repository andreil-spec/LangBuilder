from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from langflow.api.utils import CurrentActiveUser
from langflow.graph.graph.schema import GraphDump
from langflow.services.auth.authorization_patterns import get_authorized_user
from langflow.services.database.models.user.model import User

router = APIRouter(prefix="/starter-projects", tags=["Flows"])


@router.get("/", status_code=200)
async def get_starter_projects(
    current_user: Annotated[User, Depends(get_authorized_user)],
) -> list[GraphDump]:
    """Get a list of starter projects."""
    from langflow.initial_setup.load import get_starter_projects_dump

    try:
        return get_starter_projects_dump()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
