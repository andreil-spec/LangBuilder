"""Test suite for projects RBAC API endpoints."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import HTTPException, status
from sqlmodel.ext.asyncio.session import AsyncSession

from langflow.api.v1.rbac.projects import (
    create_project,
    delete_project,
    get_project,
    get_project_statistics,
    list_project_environments,
    list_project_flows,
    list_projects,
    update_project,
)
from langflow.services.database.models.rbac.project import (
    Project,
    ProjectCreate,
    ProjectUpdate,
)
from langflow.services.database.models.rbac.workspace import Workspace
from langflow.services.database.models.user.model import User
from langflow.services.rbac.permission_engine import PermissionEngine, PermissionResult


@pytest.fixture
def mock_user():
    """Create a mock user for testing."""
    user = MagicMock(spec=User)
    user.id = uuid4()
    user.username = "testuser"
    user.is_superuser = False
    return user


@pytest.fixture
def mock_session():
    """Create a mock database session."""
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def mock_permission_engine():
    """Create a mock permission engine."""
    engine = AsyncMock(spec=PermissionEngine)
    engine.check_permission.return_value = PermissionResult(
        allowed=True,
        reason="Test permission granted",
        source="test",
        cached=False
    )
    return engine


@pytest.fixture
def sample_workspace():
    """Create a sample workspace for testing."""
    workspace = MagicMock(spec=Workspace)
    workspace.id = uuid4()
    workspace.name = "Test Workspace"
    workspace.is_deleted = False
    return workspace


@pytest.fixture
def sample_project():
    """Create a sample project for testing."""
    project = MagicMock(spec=Project)
    project.id = uuid4()
    project.name = "Test Project"
    project.description = "A test project"
    project.workspace_id = uuid4()
    project.owner_id = uuid4()
    project.is_active = True
    project.is_archived = False
    project.created_at = datetime.now(timezone.utc)
    project.updated_at = datetime.now(timezone.utc)
    return project


@pytest.fixture
def project_create_data():
    """Create project creation data."""
    return ProjectCreate(
        name="New Project",
        description="A new project for testing",
        workspace_id=uuid4()
    )


class TestCreateProject:
    """Test project creation endpoint."""

    @pytest.mark.asyncio
    async def test_create_project_success(self, mock_session, mock_user, mock_permission_engine,
                                         project_create_data, sample_workspace):
        """Test successful project creation."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock no existing project
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        # Mock project creation
        created_project = MagicMock(spec=Project)
        created_project.id = uuid4()
        created_project.name = project_create_data.name
        created_project.owner_id = mock_user.id

        mock_session.refresh = AsyncMock()

        with patch("langflow.api.v1.rbac.projects.Project") as MockProject:
            MockProject.return_value = created_project

            result = await create_project(
                project_data=project_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

            # Verify project was created
            mock_session.add.assert_called_once()
            mock_session.commit.assert_called_once()
            mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_project_workspace_not_found(self, mock_session, mock_user,
                                                     mock_permission_engine, project_create_data):
        """Test project creation with non-existent workspace."""
        # Mock no workspace found
        mock_session.get.return_value = None

        with pytest.raises(HTTPException) as exc_info:
            await create_project(
                project_data=project_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_404_NOT_FOUND
        assert "Workspace not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_project_permission_denied(self, mock_session, mock_user,
                                                   mock_permission_engine, project_create_data,
                                                   sample_workspace):
        """Test project creation with insufficient permissions."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock permission denied
        mock_permission_engine.check_permission.return_value = PermissionResult(
            allowed=False,
            reason="Insufficient permissions",
            source="test",
            cached=False
        )

        with pytest.raises(HTTPException) as exc_info:
            await create_project(
                project_data=project_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN
        assert "Insufficient permissions" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_create_project_duplicate_name(self, mock_session, mock_user,
                                                mock_permission_engine, project_create_data,
                                                sample_workspace):
        """Test project creation with duplicate name."""
        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock existing project
        existing_project = MagicMock(spec=Project)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_project
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await create_project(
                project_data=project_create_data,
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST
        assert "already exists" in exc_info.value.detail


class TestListProjects:
    """Test project listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_projects_success(self, mock_session, mock_user, mock_permission_engine,
                                        sample_project):
        """Test successful project listing."""
        # Mock database query result
        mock_result = AsyncMock()
        mock_result.all.return_value = [sample_project]
        mock_session.exec.return_value = mock_result

        result = await list_projects(
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine,
            workspace_id=None,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called()
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_list_projects_with_workspace_filter(self, mock_session, mock_user,
                                                      mock_permission_engine, sample_workspace):
        """Test project listing with workspace filter."""
        workspace_id = sample_workspace.id

        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock empty results
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_projects(
            session=mock_session,
            current_user=mock_user,
            permission_engine=mock_permission_engine,
            workspace_id=workspace_id,
            skip=0,
            limit=100
        )

        assert result == []

    @pytest.mark.asyncio
    async def test_list_projects_workspace_access_denied(self, mock_session, mock_user,
                                                        mock_permission_engine, sample_workspace):
        """Test project listing with workspace access denied."""
        workspace_id = sample_workspace.id

        # Mock workspace lookup
        mock_session.get.return_value = sample_workspace

        # Mock permission denied
        mock_permission_engine.check_permission.return_value = PermissionResult(
            allowed=False,
            reason="Access denied",
            source="test",
            cached=False
        )

        with pytest.raises(HTTPException) as exc_info:
            await list_projects(
                session=mock_session,
                current_user=mock_user,
                permission_engine=mock_permission_engine,
                workspace_id=workspace_id,
                skip=0,
                limit=100
            )

        assert exc_info.value.status_code == status.HTTP_403_FORBIDDEN


class TestGetProject:
    """Test get project endpoint."""

    @pytest.mark.asyncio
    async def test_get_project_success(self, sample_project):
        """Test successful project retrieval."""
        project_id = sample_project.id

        result = await get_project(
            project_id=project_id,
            session=MagicMock(),
            current_user=MagicMock(),
            project=sample_project
        )

        # Verify project is returned (mocked dependency handles permission check)
        assert result.id == str(sample_project.id)


class TestUpdateProject:
    """Test project update endpoint."""

    @pytest.mark.asyncio
    async def test_update_project_success(self, mock_session, mock_user, sample_project):
        """Test successful project update."""
        project_id = sample_project.id
        update_data = ProjectUpdate(
            name="Updated Project",
            description="Updated description"
        )

        # Mock no existing project with same name
        mock_result = AsyncMock()
        mock_result.first.return_value = None
        mock_session.exec.return_value = mock_result

        mock_session.refresh = AsyncMock()

        result = await update_project(
            project_id=project_id,
            project_data=update_data,
            session=mock_session,
            current_user=mock_user,
            project=sample_project
        )

        # Verify update was committed
        mock_session.commit.assert_called_once()
        mock_session.refresh.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_project_duplicate_name(self, mock_session, mock_user, sample_project):
        """Test project update with duplicate name."""
        project_id = sample_project.id
        update_data = ProjectUpdate(name="Existing Name")

        # Mock existing project with same name
        existing_project = MagicMock(spec=Project)
        mock_result = AsyncMock()
        mock_result.first.return_value = existing_project
        mock_session.exec.return_value = mock_result

        with pytest.raises(HTTPException) as exc_info:
            await update_project(
                project_id=project_id,
                project_data=update_data,
                session=mock_session,
                current_user=mock_user,
                project=sample_project
            )

        assert exc_info.value.status_code == status.HTTP_400_BAD_REQUEST


class TestDeleteProject:
    """Test project deletion endpoint."""

    @pytest.mark.asyncio
    async def test_delete_project_success(self, mock_session, mock_user, sample_project):
        """Test successful project deletion (archive)."""
        project_id = sample_project.id

        await delete_project(
            project_id=project_id,
            session=mock_session,
            current_user=mock_user,
            project=sample_project
        )

        # Verify project was archived
        assert sample_project.is_archived is True
        assert sample_project.archived_at is not None
        mock_session.commit.assert_called_once()


class TestListProjectEnvironments:
    """Test project environments listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_project_environments_success(self, mock_session, mock_user, sample_project):
        """Test successful project environments listing."""
        project_id = sample_project.id

        # Mock environment query result
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_project_environments(
            project_id=project_id,
            session=mock_session,
            current_user=mock_user,
            project=sample_project,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called_once()
        assert result == []


class TestListProjectFlows:
    """Test project flows listing endpoint."""

    @pytest.mark.asyncio
    async def test_list_project_flows_success(self, mock_session, mock_user, sample_project):
        """Test successful project flows listing."""
        project_id = sample_project.id

        # Mock flow query result
        mock_result = AsyncMock()
        mock_result.all.return_value = []
        mock_session.exec.return_value = mock_result

        result = await list_project_flows(
            project_id=project_id,
            session=mock_session,
            current_user=mock_user,
            project=sample_project,
            skip=0,
            limit=100
        )

        # Verify query was executed
        mock_session.exec.assert_called_once()
        assert result == []


class TestGetProjectStatistics:
    """Test project statistics endpoint."""

    @pytest.mark.asyncio
    async def test_get_project_statistics_success(self, mock_session, mock_user, sample_project):
        """Test successful project statistics retrieval."""
        project_id = sample_project.id

        # Mock count queries
        mock_session.exec.side_effect = [
            AsyncMock(one=lambda: 3),   # total_environments
            AsyncMock(one=lambda: 2),   # active_environments
            AsyncMock(one=lambda: 5),   # total_flows
            AsyncMock(one=lambda: 8),   # total_deployments
            AsyncMock(one=lambda: 6),   # successful_deployments
            AsyncMock(one=lambda: 2),   # failed_deployments
            AsyncMock(first=lambda: None), # last_deployment
        ]

        result = await get_project_statistics(
            project_id=project_id,
            session=mock_session,
            current_user=mock_user,
            project=sample_project
        )

        # Verify statistics
        assert result.project_id == project_id
        assert result.total_environments == 3
        assert result.active_environments == 2
        assert result.total_flows == 5
        assert result.total_deployments == 8
        assert result.successful_deployments == 6
        assert result.failed_deployments == 2
        assert result.last_deployment_at is None
