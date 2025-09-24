import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError, normalizeListResponse } from "./error-handler";

export enum GroupType {
  LOCAL = "local",
  SYNCED = "synced",
  DYNAMIC = "dynamic",
  TEAM = "team",
  PROJECT = "project",
}

export interface UserGroup {
  id: string;
  name: string;
  description: string | null;
  workspace_id: string;
  workspace_name?: string | null;
  group_type: GroupType;
  external_id: string | null;
  is_active: boolean;
  sync_enabled: boolean;
  sync_last_run: string | null;
  sync_status: string | null;
  tags: string[] | null;
  created_at: string;
  updated_at: string;
  created_by_id: string;
  member_count?: number;
  role_count?: number;
}

export interface UserGroupMembership {
  id: string;
  group_id: string;
  user_id: string;
  user_name: string | null;
  user_email: string | null;
  membership_type: string;
  external_id: string | null;
  is_active: boolean;
  added_at: string;
  added_by_id: string | null;
}

interface GetUserGroupsQueryParams {
  workspace_id?: string;
  page?: number;
  page_size?: number;
  search?: string;
  group_type?: GroupType;
  is_active?: boolean;
}

interface UserGroupListResponse {
  user_groups: UserGroup[];
  total_count: number;
  page: number;
  page_size: number;
  has_next: boolean;
  has_previous: boolean;
}

export interface CreateUserGroupData {
  name: string;
  description?: string;
  workspace_id: string;
  group_type?: GroupType;
  external_id?: string;
  sync_enabled?: boolean;
  tags?: string[];
}

interface UpdateUserGroupData {
  name?: string;
  description?: string;
  group_type?: GroupType;
  external_id?: string;
  is_active?: boolean;
  sync_enabled?: boolean;
  tags?: string[];
}

interface CreateUserGroupMembershipData {
  group_id: string;
  user_id: string;
  membership_type?: string;
  external_id?: string;
}

interface SyncUserGroupData {
  group_id: string;
  force_full_sync?: boolean;
}

// Get User Groups
export const useGetUserGroups: useMutationFunctionType<
  undefined,
  GetUserGroupsQueryParams,
  UserGroupListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getUserGroups({
    workspace_id,
    page = 1,
    page_size = 50,
    search,
    group_type,
    is_active,
  }: GetUserGroupsQueryParams): Promise<UserGroupListResponse> {
    try {
      const params = new URLSearchParams();
      if (workspace_id) {
        params.append("workspace_id", workspace_id);
      }
      params.append("page", page.toString());
      params.append("size", page_size.toString());

      if (search) {
        params.append("search", search);
      }
      if (group_type) {
        params.append("group_type", group_type);
      }
      if (is_active !== undefined) {
        params.append("is_active", is_active.toString());
      }

      const url = `${getURL("RBAC")}/user-groups/?${params.toString()}`;
      const res = await api.get(url);

      if (res.status === 200) {
        const normalized = normalizeListResponse<UserGroup>(
          res.data,
          "user_groups",
          page,
          page_size,
        );

        return {
          user_groups: normalized.items,
          total_count: normalized.total_count,
          page: normalized.page,
          page_size: normalized.page_size,
          has_next: normalized.has_next,
          has_previous: normalized.has_previous,
        };
      }

      return {
        user_groups: [],
        total_count: 0,
        page: page,
        page_size: page_size,
        has_next: false,
        has_previous: false,
      };
    } catch (error) {
      handleRBACError(error, "user groups list");
    }
  }

  const mutation: UseMutationResult<
    UserGroupListResponse,
    any,
    GetUserGroupsQueryParams
  > = mutate(["useGetUserGroups"], getUserGroups, options || {});

  return mutation;
};

// Create User Group
export const useCreateUserGroup: useMutationFunctionType<
  undefined,
  CreateUserGroupData,
  UserGroup
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function createUserGroup(
    data: CreateUserGroupData,
  ): Promise<UserGroup> {
    try {
      const url = `${getURL("RBAC")}/user-groups/`;
      const res = await api.post(url, data);

      if (res.status === 201) {
        return res.data;
      }

      throw new Error("Failed to create user group");
    } catch (error) {
      handleRBACError(error, "user group creation");
    }
  }

  const mutation: UseMutationResult<UserGroup, any, CreateUserGroupData> =
    mutate(["useCreateUserGroup"], createUserGroup, options || {});

  return mutation;
};

// Update User Group
export const useUpdateUserGroup: useMutationFunctionType<
  undefined,
  { group_id: string; data: UpdateUserGroupData },
  UserGroup
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function updateUserGroup({
    group_id,
    data,
  }: {
    group_id: string;
    data: UpdateUserGroupData;
  }): Promise<UserGroup> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${group_id}`;
      const res = await api.put(url, data);

      if (res.status === 200) {
        return res.data;
      }

      throw new Error("Failed to update user group");
    } catch (error) {
      handleRBACError(error, "user group update");
    }
  }

  const mutation: UseMutationResult<
    UserGroup,
    any,
    { group_id: string; data: UpdateUserGroupData }
  > = mutate(["useUpdateUserGroup"], updateUserGroup, options || {});

  return mutation;
};

// Delete User Group
export const useDeleteUserGroup: useMutationFunctionType<
  undefined,
  { group_id: string },
  void
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function deleteUserGroup({
    group_id,
  }: {
    group_id: string;
  }): Promise<void> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${group_id}`;
      const res = await api.delete(url);

      if (res.status === 204) {
        return;
      }

      throw new Error("Failed to delete user group");
    } catch (error) {
      handleRBACError(error, "user group deletion");
    }
  }

  const mutation: UseMutationResult<void, any, { group_id: string }> = mutate(
    ["useDeleteUserGroup"],
    deleteUserGroup,
    options || {},
  );

  return mutation;
};

// Get User Group Members
export const useGetUserGroupMembers: useMutationFunctionType<
  undefined,
  { group_id: string },
  UserGroupMembership[]
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getUserGroupMembers({
    group_id,
  }: {
    group_id: string;
  }): Promise<UserGroupMembership[]> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${group_id}/members`;
      const res = await api.get(url);

      if (res.status === 200) {
        return Array.isArray(res.data) ? res.data : [];
      }

      return [];
    } catch (error) {
      handleRBACError(error, "user group members list");
    }
  }

  const mutation: UseMutationResult<
    UserGroupMembership[],
    any,
    { group_id: string }
  > = mutate(["useGetUserGroupMembers"], getUserGroupMembers, options || {});

  return mutation;
};

// Add User Group Member
export const useAddUserGroupMember: useMutationFunctionType<
  undefined,
  CreateUserGroupMembershipData,
  UserGroupMembership
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function addUserGroupMember(
    data: CreateUserGroupMembershipData,
  ): Promise<UserGroupMembership> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${data.group_id}/members`;
      const res = await api.post(url, data);

      if (res.status === 201) {
        return res.data;
      }

      throw new Error("Failed to add user to group");
    } catch (error) {
      handleRBACError(error, "user group member addition");
    }
  }

  const mutation: UseMutationResult<
    UserGroupMembership,
    any,
    CreateUserGroupMembershipData
  > = mutate(["useAddUserGroupMember"], addUserGroupMember, options || {});

  return mutation;
};

// Remove User Group Member
export const useRemoveUserGroupMember: useMutationFunctionType<
  undefined,
  { group_id: string; user_id: string },
  void
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function removeUserGroupMember({
    group_id,
    user_id,
  }: {
    group_id: string;
    user_id: string;
  }): Promise<void> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${group_id}/members/${user_id}`;
      const res = await api.delete(url);

      if (res.status === 204) {
        return;
      }

      throw new Error("Failed to remove user from group");
    } catch (error) {
      handleRBACError(error, "user group member removal");
    }
  }

  const mutation: UseMutationResult<
    void,
    any,
    { group_id: string; user_id: string }
  > = mutate(
    ["useRemoveUserGroupMember"],
    removeUserGroupMember,
    options || {},
  );

  return mutation;
};

// Sync User Group
export const useSyncUserGroup: useMutationFunctionType<
  undefined,
  SyncUserGroupData,
  { message: string; sync_status: string }
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function syncUserGroup(
    data: SyncUserGroupData,
  ): Promise<{ message: string; sync_status: string }> {
    try {
      const url = `${getURL("RBAC")}/user-groups/${data.group_id}/sync`;
      const res = await api.post(url, data);

      if (res.status === 200) {
        return res.data;
      }

      throw new Error("Failed to sync user group");
    } catch (error) {
      handleRBACError(error, "user group sync");
    }
  }

  const mutation: UseMutationResult<
    { message: string; sync_status: string },
    any,
    SyncUserGroupData
  > = mutate(["useSyncUserGroup"], syncUserGroup, options || {});

  return mutation;
};

// Helper function to get group type color
export function getGroupTypeColor(groupType: GroupType): string {
  switch (groupType) {
    case GroupType.LOCAL:
      return "blue";
    case GroupType.SYNCED:
      return "green";
    case GroupType.TEAM:
      return "purple";
    case GroupType.PROJECT:
      return "orange";
    case GroupType.DYNAMIC:
      return "cyan";
    default:
      return "gray";
  }
}

// Helper function to format group type for display
export function formatGroupType(groupType: GroupType): string {
  return groupType.toUpperCase();
}
