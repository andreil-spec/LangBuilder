export default function SystemSettings() {
  return (
    <div className="p-6">
      <h2 className="text-xl font-semibold mb-6">System Settings</h2>
      <div className="space-y-6">
        <div className="border rounded-lg p-4">
          <h3 className="text-lg font-medium mb-4">
            Global RBAC Configuration
          </h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-medium">Enable RBAC</span>
                <p className="text-sm text-gray-600">
                  Toggle role-based access control system-wide
                </p>
              </div>
              <input type="checkbox" defaultChecked className="toggle" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <span className="font-medium">Strict Mode</span>
                <p className="text-sm text-gray-600">
                  Require explicit permissions for all actions
                </p>
              </div>
              <input type="checkbox" className="toggle" />
            </div>
          </div>
        </div>

        <div className="border rounded-lg p-4">
          <h3 className="text-lg font-medium mb-4">Security Policies</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">
                Session Timeout (minutes)
              </label>
              <input
                type="number"
                defaultValue="30"
                className="border rounded px-3 py-2 w-32"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">
                Max Failed Login Attempts
              </label>
              <input
                type="number"
                defaultValue="5"
                className="border rounded px-3 py-2 w-32"
              />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
