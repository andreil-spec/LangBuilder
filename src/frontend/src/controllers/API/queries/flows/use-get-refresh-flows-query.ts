import type { UseQueryOptions } from "@tanstack/react-query";
import { AxiosError } from "axios";
import buildQueryStringUrl from "@/controllers/utils/create-query-param-string";
import useAlertStore from "@/stores/alertStore";
import useFlowsManagerStore from "@/stores/flowsManagerStore";
import { useTypesStore } from "@/stores/typesStore";
import type { useQueryFunctionType } from "@/types/api";
import type { FlowType, PaginatedFlowsType } from "@/types/flow";
import {
  extractFieldsFromComponenents,
  processFlows,
} from "@/utils/reactflowUtils";
import { api } from "../../api";
import { getURL } from "../../helpers/constants";
import { UseRequestProcessor } from "../../services/request-processor";

interface GetFlowsParams {
  components_only?: boolean;
  get_all?: boolean;
  header_flows?: boolean;
  folder_id?: string;
  remove_example_flows?: boolean;
  page?: number;
  size?: number;
}

const addQueryParams = (url: string, params: GetFlowsParams): string => {
  return buildQueryStringUrl(url, params);
};

export const useGetRefreshFlowsQuery: useQueryFunctionType<
  GetFlowsParams,
  FlowType[] | PaginatedFlowsType
> = (params, options) => {
  const { query } = UseRequestProcessor();
  const setFlows = useFlowsManagerStore((state) => state.setFlows);
  const setErrorData = useAlertStore((state) => state.setErrorData);

  const getFlowsFn = async (
    params: GetFlowsParams,
  ): Promise<FlowType[] | PaginatedFlowsType> => {
    try {
      const url = addQueryParams(`${getURL("FLOWS")}/`, params);
      const { data: dbDataFlows } = await api.get<FlowType[]>(url);

      if (params.components_only) {
        return dbDataFlows;
      }

      const { data: dbDataComponents } = await api.get<FlowType[]>(
        addQueryParams(`${getURL("FLOWS")}/`, {
          components_only: true,
          get_all: true,
        }),
      );

      if (dbDataComponents) {
        const { data } = processFlows(dbDataComponents);
        useTypesStore.setState((state) => ({
          data: { ...state.data, ["saved_components"]: data },
          ComponentFields: extractFieldsFromComponenents({
            ...state.data,
            ["saved_components"]: data,
          }),
        }));
      }

      if (dbDataFlows) {
        const flows = Array.isArray(dbDataFlows)
          ? dbDataFlows
          : (dbDataFlows as { items: FlowType[] }).items;
        setFlows(flows);
        return flows;
      }

      return [];
    } catch (e) {
      if (e instanceof AxiosError) {
        const status = e.response?.status || e.status;

        // Don't show error popups for authentication/authorization issues
        // These are expected in development when auth is not properly configured
        if (status === 401 || status === 403) {
          console.warn(
            "⚠️ Flows API authentication error - returning empty flows:",
            e.response?.data,
          );
          return [];
        }

        // Only show error popup for actual server errors
        if (status >= 500) {
          setErrorData({
            title: "Could not load flows from database",
          });
        } else {
          // For other errors (like 404, 422), just log them
          console.warn("⚠️ Flows API error - returning empty flows:", {
            status,
            data: e.response?.data,
          });
          return [];
        }
      }
      throw e;
    }
  };

  const queryResult = query(
    ["useGetRefreshFlowsQuery", params],
    () => getFlowsFn(params || {}),
    options as UseQueryOptions,
  );

  return queryResult;
};
