import type { UseMutationResult } from "@tanstack/react-query";
import type { useMutationFunctionType } from "../../../../types/api";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

import type { Permission } from "./use-get-permissions";

interface GetRolePermissionsQueryParams {
  roleId: string;
}

export const useGetRolePermissions: useMutationFunctionType<
  undefined,
  GetRolePermissionsQueryParams,
  Permission[]
> = (options?) => {
  const { mutate } = UseRequestProcessor();

  async function getRolePermissions({
    roleId,
  }: GetRolePermissionsQueryParams): Promise<Permission[]> {
    const url = `${getURL("RBAC")}/roles/${roleId}/permissions`;

    const res = await api.get(url);
    if (res.status === 200) {
      return res.data;
    }
    return [];
  }

  const mutation: UseMutationResult<
    Permission[],
    any,
    GetRolePermissionsQueryParams
  > = mutate(["useGetRolePermissions"], getRolePermissions, options);

  return mutation;
};
