import { useState } from "react";

export default function ComplianceReporting() {
  const [reportType, setReportType] = useState("");
  const [reports] = useState([
    {
      id: "1",
      name: "User Access Report",
      type: "Access",
      generated: "2024-01-15",
      status: "Ready",
    },
    {
      id: "2",
      name: "Role Assignment Audit",
      type: "Audit",
      generated: "2024-01-14",
      status: "Generating",
    },
    {
      id: "3",
      name: "Permission Matrix",
      type: "Matrix",
      generated: "2024-01-13",
      status: "Ready",
    },
  ]);

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-semibold">Compliance Reporting</h2>
        <button className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700">
          Generate Report
        </button>
      </div>

      <div className="flex space-x-4 mb-6">
        <select
          value={reportType}
          onChange={(e) => setReportType(e.target.value)}
          className="border rounded px-3 py-2"
        >
          <option value="">Select Report Type</option>
          <option value="user-access">User Access Report</option>
          <option value="role-assignments">Role Assignments</option>
          <option value="audit-logs">Audit Logs</option>
          <option value="permission-matrix">Permission Matrix</option>
        </select>

        <div className="flex items-center space-x-2">
          <span className="text-sm text-gray-600">Date Range:</span>
          <input type="date" className="border rounded px-3 py-2" />
          <span className="text-gray-400">to</span>
          <input type="date" className="border rounded px-3 py-2" />
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <h3 className="font-medium text-blue-900">Total Users</h3>
          <p className="text-2xl font-bold text-blue-700">127</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <h3 className="font-medium text-green-900">Active Roles</h3>
          <p className="text-2xl font-bold text-green-700">8</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <h3 className="font-medium text-purple-900">Audit Events</h3>
          <p className="text-2xl font-bold text-purple-700">1,247</p>
        </div>
      </div>

      <div className="border rounded-lg overflow-hidden">
        <div className="bg-gray-50 px-4 py-3">
          <h3 className="font-medium">Recent Reports</h3>
        </div>
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Report Name
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Type
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Generated
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Status
              </th>
              <th className="px-4 py-3 text-left text-sm font-medium text-gray-700">
                Actions
              </th>
            </tr>
          </thead>
          <tbody className="divide-y">
            {reports.map((report) => (
              <tr key={report.id} className="hover:bg-gray-50">
                <td className="px-4 py-3 font-medium">{report.name}</td>
                <td className="px-4 py-3">{report.type}</td>
                <td className="px-4 py-3 text-gray-600">{report.generated}</td>
                <td className="px-4 py-3">
                  <span
                    className={`px-2 py-1 rounded text-xs ${
                      report.status === "Ready"
                        ? "bg-green-100 text-green-800"
                        : "bg-yellow-100 text-yellow-800"
                    }`}
                  >
                    {report.status}
                  </span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex space-x-2">
                    <button className="text-blue-600 hover:text-blue-800 text-sm">
                      Download
                    </button>
                    <button className="text-gray-600 hover:text-gray-800 text-sm">
                      View
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
