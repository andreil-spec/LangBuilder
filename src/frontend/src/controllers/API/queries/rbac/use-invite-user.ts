import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

export interface InviteUserData {
  workspace_id: string;
  email: string;
  role_id?: string;
  message?: string;
}

export interface InviteUserResponse {
  message: string;
  invitation_id: string;
  expires_at: string;
}

export const useInviteUser: useMutationFunctionType<
  undefined,
  InviteUserData,
  InviteUserResponse
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function inviteUser(
    inviteData: InviteUserData,
  ): Promise<InviteUserResponse> {
    const { workspace_id, ...data } = inviteData;
    const res = await api.post(
      `${getURL("RBAC")}/workspaces/${workspace_id}/invite`,
      data,
    );
    if (res.status === 200) {
      return res.data;
    }
    throw new Error(`Failed to invite user: ${res.status}`);
  }

  const mutation: UseMutationResult<InviteUserResponse, any, InviteUserData> =
    mutate(["useInviteUser"], inviteUser, options);

  return mutation;
};
