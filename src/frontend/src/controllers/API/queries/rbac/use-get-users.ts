import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";
import { handleRBACError } from "./error-handler";

export interface User {
  id: string;
  username: string;
  profile_image: string | null;
  store_api_key: string | null;
  is_active: boolean;
  is_superuser: boolean;
  create_at: string;
  updated_at: string;
  last_login_at: string | null;
  optins: {
    github_starred: boolean;
    dialog_dismissed: boolean;
    discord_clicked: boolean;
  };
}

interface GetUsersQueryParams {
  skip?: number;
  limit?: number;
}

interface UsersListResponse {
  users: User[];
  total_count: number;
}

// Get Users
export const useGetUsers: useMutationFunctionType<
  undefined,
  GetUsersQueryParams,
  UsersListResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getUsers({
    skip = 0,
    limit = 100,
  }: GetUsersQueryParams = {}): Promise<UsersListResponse> {
    try {
      const params = new URLSearchParams();
      params.append("skip", skip.toString());
      params.append("limit", limit.toString());

      const url = `/api/v1/users/?${params.toString()}`;
      const res = await api.get(url);

      if (res.status === 200) {
        return {
          users: res.data.users || [],
          total_count: res.data.total_count || 0,
        };
      }

      return {
        users: [],
        total_count: 0,
      };
    } catch (error) {
      handleRBACError(error, "users list");
    }
  }

  const mutation: UseMutationResult<
    UsersListResponse,
    any,
    GetUsersQueryParams
  > = mutate(["useGetUsers"], getUsers, options || {});

  return mutation;
};
