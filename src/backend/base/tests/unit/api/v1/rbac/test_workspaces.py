"""Test suite for workspace RBAC API endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.v1.rbac.workspaces import (
    create_workspace,
    delete_workspace,
    get_workspace,
    get_workspace_statistics,
    invite_user_to_workspace,
    list_workspace_projects,
    list_workspace_users,
    list_workspaces,
    update_workspace,
)
from langflow.services.database.models.rbac.workspace import (
    Workspace,
    WorkspaceCreate,
    WorkspaceInvitation,
    WorkspaceUpdate,
)
from langflow.services.database.models.user.model import User


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.is_superuser = False
    return user


@pytest.fixture
def mock_superuser():
    """Create a mock superuser for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "admin"
    user.is_superuser = True
    return user


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def sample_workspace():
    """Create a sample workspace for testing."""
    workspace = MagicMock(spec=Workspace)
    workspace.id = uuid4()
    workspace.name = "Test Workspace"
    workspace.description = "A test workspace"
    workspace.owner_id = uuid4()
    workspace.is_deleted = False
    workspace.is_active = True
    workspace.created_at = datetime.now(timezone.utc)
    workspace.updated_at = datetime.now(timezone.utc)
    return workspace


@pytest.fixture
def workspace_create_data():
    """Create workspace creation data."""
    return WorkspaceCreate(
        name="New Workspace",
        description="A new workspace for testing",
        organization="Test Org"
    )


class TestCreateWorkspace:
    """Test workspace creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_workspace_success(self, mock_session, mock_user, workspace_create_data):
        """Test successful workspace creation."""
        # Mock database query to return no existing workspace
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        # Mock workspace creation
        created_workspace = MagicMock(spec=Workspace)
        created_workspace.id = uuid4()
        created_workspace.name = workspace_create_data.name
        created_workspace.owner_id = mock_user.id

        mock_session.refresh = AsyncMock()

        with patch("langflow.api.v1.rbac.workspaces.Workspace") as MockWorkspace:
            MockWorkspace.return_value = created_workspace

            result = await create_workspace(
                workspace_data=workspace_create_data,
                session=mock_session,
                current_user=mock_user
            )

            # Verify workspace was created
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_workspace_duplicate_name(self, mock_session, mock_user, workspace_create_data):
        """Test workspace creation with duplicate name."""
        # Mock existing workspace
        existing_workspace = MagicMock(spec=Workspace)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_workspace
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await create_workspace(
                workspace_data=workspace_create_data,
                session=mock_session,
                current_user=mock_user
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail


class TestListWorkspaces:
    """Test workspace listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_workspaces_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace listing."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = [sample_workspace]
        mock_session.exec.return_value = mock_result

        result = await list_workspaces(
            session=mock_session,
            current_user=mock_user,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called_once()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_workspaces_with_filters(self, mock_session, mock_user):
        """Test workspace listing with search filters."""
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_workspaces(
            session=mock_session,
            current_user=mock_user,
            search="test",
            organization="Test Org",
            is_active=True,
            skip=0,
            limit=50
        )

        mock_session.exec.assert_called_once()
        assert result == []


class TestGetWorkspace:
    """Test get workspace endpoint."""

    @pytest.mark.asyncio
    async def test_get_workspace_success(self, sample_workspace):
        """Test successful workspace retrieval."""
        workspace_id = sample_workspace.id

        result = await get_workspace(
            workspace_id=workspace_id,
            session=MagicMock(),
            current_user=MagicMock(),
            workspace=sample_workspace
        )

        # Verify workspace is returned (mocked dependency handles permission check)
        assert result.id == str(sample_workspace.id)


class TestUpdateWorkspace:
    """Test workspace update endpoint."""

    @pytest.mark.asyncio
    async def test_update_workspace_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace update."""
        workspace_id = sample_workspace.id
        update_data = WorkspaceUpdate(
            name="Updated Workspace",
            description="Updated description"
        )

        # Mock no existing workspace with same name
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        mock_session.refresh = AsyncMock()

        result = await update_workspace(
            workspace_id=workspace_id,
            workspace_data=update_data,
            session=mock_session,
            current_user=mock_user,
            workspace=sample_workspace
        )

        # Verify update was committed
        mock_session.commit.assert_called_once()
        mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_workspace_duplicate_name(self, mock_session, mock_user, sample_workspace):
        """Test workspace update with duplicate name."""
        workspace_id = sample_workspace.id
        update_data = WorkspaceUpdate(name="Existing Name")

        # Mock existing workspace with same name
        existing_workspace = MagicMock(spec=Workspace)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_workspace
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await update_workspace(
                workspace_id=workspace_id,
                workspace_data=update_data,
                session=mock_session,
                current_user=mock_user,
                workspace=sample_workspace
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


class TestDeleteWorkspace:
    """Test workspace deletion endpoint."""

    @pytest.mark.asyncio
    async def test_delete_workspace_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace deletion (soft delete)."""
        workspace_id = sample_workspace.id

        await delete_workspace(
            workspace_id=workspace_id,
            session=mock_session,
            current_user=mock_user,
            workspace=sample_workspace
        )

        # Verify soft delete was performed
        assert sample_workspace.is_deleted is True
        assert sample_workspace.deletion_requested_at is not None
        mock_session.commit.assert_called_once()


class TestInviteUserToWorkspace:
    """Test workspace user invitation endpoint."""

    @pytest.mark.asyncio
    async def test_invite_user_success(self, mock_session, mock_user, sample_workspace):
        """Test successful user invitation."""
        workspace_id = sample_workspace.id
        invitation_data = {
            "email": "newuser@example.com",
            "role_id": str(uuid4())
        }

        # Mock no existing invitation
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        with patch("langflow.api.v1.rbac.workspaces.WorkspaceInvitation") as MockInvitation:
            mock_invitation = MagicMock()
            mock_invitation.id = uuid4()
            mock_invitation.expires_at = datetime.now(timezone.utc)
            MockInvitation.return_value = mock_invitation

            result = await invite_user_to_workspace(
                workspace_id=workspace_id,
                invitation_data=invitation_data,
                session=mock_session,
                current_user=mock_user,
                workspace=sample_workspace
            )

            # Verify invitation was created
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            assert "invitation_id" in result

    @pytest.mark.asyncio
    async def test_invite_user_missing_email(self, mock_session, mock_user, sample_workspace):
        """Test invitation with missing email."""
        workspace_id = sample_workspace.id
        invitation_data = {"role_id": str(uuid4())}

        with pytest.raises(HTTPException) as exc_info:
            await invite_user_to_workspace(
                workspace_id=workspace_id,
                invitation_data=invitation_data,
                session=mock_session,
                current_user=mock_user,
                workspace=sample_workspace
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "Email is required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_invite_user_duplicate_invitation(self, mock_session, mock_user, sample_workspace):
        """Test invitation when user already has pending invitation."""
        workspace_id = sample_workspace.id
        invitation_data = {
            "email": "existing@example.com",
            "role_id": str(uuid4())
        }

        # Mock existing invitation
        existing_invitation = MagicMock(spec=WorkspaceInvitation)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_invitation
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await invite_user_to_workspace(
                workspace_id=workspace_id,
                invitation_data=invitation_data,
                session=mock_session,
                current_user=mock_user,
                workspace=sample_workspace
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "pending invitation" in exc_info.value.detail


class TestListWorkspaceUsers:
    """Test workspace users listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_workspace_users_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace users listing."""
        workspace_id = sample_workspace.id
        sample_workspace.owner = mock_user

        result = await list_workspace_users(
            workspace_id=workspace_id,
            session=mock_session,
            current_user=mock_user,
            workspace=sample_workspace,
            skip=0,
            limit=100
        )

        # Verify owner is in the list
        assert len(result) == 1
        assert result[0]["user_id"] == str(sample_workspace.owner_id)
        assert "workspace_owner" in result[0]["roles"]


class TestListWorkspaceProjects:
    """Test workspace projects listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_workspace_projects_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace projects listing."""
        workspace_id = sample_workspace.id

        # Mock project query result
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_workspace_projects(
            workspace_id=workspace_id,
            session=mock_session,
            current_user=mock_user,
            workspace=sample_workspace,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called_once()
        assert result == []


class TestGetWorkspaceStatistics:
    """Test workspace statistics endpoint."""

    @pytest.mark.asyncio
    async def test_get_workspace_statistics_success(self, mock_session, mock_user, sample_workspace):
        """Test successful workspace statistics retrieval."""
        workspace_id = sample_workspace.id

        # Mock count queries
        mock_session.exec.side_effect = [
            AsyncMock(one=lambda: 5),  # project_count
            AsyncMock(one=lambda: 3),  # user_count
            AsyncMock(one=lambda: 2),  # group_count
            AsyncMock(one=lambda: 10), # flow_count
        ]

        result = await get_workspace_statistics(
            workspace_id=workspace_id,
            session=mock_session,
            current_user=mock_user,
            workspace=sample_workspace
        )

        # Verify statistics
        assert result["project_count"] == 5
        assert result["user_count"] == 4  # 3 + 1 for owner
        assert result["group_count"] == 2
        assert result["flow_count"] == 10
        assert "workspace_id" in result
        assert "created_at" in result
        assert "last_updated" in result
