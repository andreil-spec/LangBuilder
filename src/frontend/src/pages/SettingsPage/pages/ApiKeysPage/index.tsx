import type { SelectionChangedEvent } from "ag-grid-community";
import { useContext, useEffect, useState } from "react";
import { PermissionGuard } from "@/components/rbac";
import {
  DEL_KEY_ERROR_ALERT,
  DEL_KEY_ERROR_ALERT_PLURAL,
  DEL_KEY_SUCCESS_ALERT,
  DEL_KEY_SUCCESS_ALERT_PLURAL,
} from "@/constants/alerts_constants";
import {
  type IApiKeysDataArray,
  useDeleteApiKey,
  useGetApiKeysQuery,
} from "@/controllers/API/queries/api-keys";
import TableComponent from "../../../../components/core/parameterRenderComponent/components/tableComponent";
import { AuthContext } from "../../../../contexts/authContext";
import useAlertStore from "../../../../stores/alertStore";
import ApiKeyHeaderComponent from "./components/ApiKeyHeader";
import { getColumnDefs } from "./helpers/column-defs";

export default function ApiKeysPage() {
  const [selectedRows, setSelectedRows] = useState<string[]>([]);
  const setSuccessData = useAlertStore((state) => state.setSuccessData);
  const setErrorData = useAlertStore((state) => state.setErrorData);
  const { userData } = useContext(AuthContext);
  const [userId, setUserId] = useState("");
  const [keysList, setKeysList] = useState<IApiKeysDataArray[]>([]);
  const { refetch } = useGetApiKeysQuery();

  async function getApiKeysQuery() {
    const { data } = await refetch();
    if (data !== undefined) {
      const updatedKeysList = data["api_keys"].map((apikey) => ({
        ...apikey,
        name: apikey.name && apikey.name !== "" ? apikey.name : "Untitled",
        last_used_at: apikey.last_used_at ?? "Never",
      }));
      setKeysList(updatedKeysList);
      setUserId(data["user_id"]);
    }
  }

  useEffect(() => {
    if (userData) {
      getApiKeysQuery();
    }
  }, [userData]);

  function resetFilter() {
    getApiKeysQuery();
  }

  const { mutate } = useDeleteApiKey();

  function handleDeleteApi() {
    for (let i = 0; i < selectedRows.length; i++) {
      mutate(
        { keyId: selectedRows[i] },
        {
          onSuccess: () => {
            resetFilter();
            setSuccessData({
              title:
                selectedRows.length === 1
                  ? DEL_KEY_SUCCESS_ALERT
                  : DEL_KEY_SUCCESS_ALERT_PLURAL,
            });
          },
          onError: (error) => {
            setErrorData({
              title:
                selectedRows.length === 1
                  ? DEL_KEY_ERROR_ALERT
                  : DEL_KEY_ERROR_ALERT_PLURAL,
              list: [error?.response?.data?.detail],
            });
          },
        },
      );
    }
  }

  const columnDefs = getColumnDefs();

  return (
    <PermissionGuard
      resource="api_key"
      action="read"
      fallback={
        <div className="flex h-full w-full items-center justify-center">
          <div className="text-center">
            <h3 className="text-lg font-medium text-muted-foreground mb-2">
              Access Denied
            </h3>
            <p className="text-sm text-muted-foreground">
              You don't have permission to view API keys.
            </p>
          </div>
        </div>
      }
      hideIfNoPermission={false}
    >
      <div className="flex h-full w-full flex-col justify-between gap-6">
        <ApiKeyHeaderComponent
          selectedRows={selectedRows}
          fetchApiKeys={getApiKeysQuery}
          userId={userId}
        />

        <div className="flex h-full w-full flex-col justify-between">
          <TableComponent
            key={"apiKeys"}
            onDelete={handleDeleteApi}
            overlayNoRowsTemplate="No data available"
            onSelectionChanged={(event: SelectionChangedEvent) => {
              setSelectedRows(event.api.getSelectedRows().map((row) => row.id));
            }}
            rowSelection="multiple"
            suppressRowClickSelection={true}
            pagination={true}
            columnDefs={columnDefs}
            rowData={keysList}
          />
        </div>
      </div>
    </PermissionGuard>
  );
}
