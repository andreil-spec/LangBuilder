import { useContext, useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { AuthContext } from "@/contexts/authContext";
import { useLoginUser } from "@/controllers/API/queries/auth/use-post-login-user";
import useAuthStore from "@/stores/authStore";

interface AuthenticationModalProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSuccess?: () => void;
}

export default function AuthenticationModal({
  open,
  onOpenChange,
  onSuccess,
}: AuthenticationModalProps) {
  const [username, setUsername] = useState("langflow");
  const [password, setPassword] = useState("langflow");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { login } = useContext(AuthContext);
  const { mutate: loginUser } = useLoginUser();
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);

  const handleLogin = () => {
    if (!username || !password) {
      setError("Please enter both username and password");
      return;
    }

    setLoading(true);
    setError(null);

    loginUser(
      { username, password },
      {
        onSuccess: (data) => {
          console.log("🔐 Login API successful:", data);
          console.log(
            "🔐 Calling AuthContext.login() with token:",
            data.access_token.substring(0, 20) + "...",
          );
          login(data.access_token, "false", data.refresh_token);

          // Add delay to ensure auth state updates before closing modal
          setTimeout(() => {
            const authState = useAuthStore.getState();
            console.log("🔐 Auth state after login:", {
              isAuthenticated: authState.isAuthenticated,
              accessToken: !!authState.accessToken,
              userData: !!authState.userData,
            });
            setLoading(false);
            onOpenChange(false);
            onSuccess?.();
          }, 200);
        },
        onError: (error) => {
          console.error("Login failed:", error);
          setError("Login failed. Please check your credentials.");
          setLoading(false);
        },
      },
    );
  };

  // If already authenticated, close modal
  if (isAuthenticated) {
    if (open) {
      onOpenChange(false);
    }
    return null;
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center space-x-2">
            <IconComponent name="Shield" className="h-5 w-5" />
            <span>Authentication Required</span>
          </DialogTitle>
          <DialogDescription>
            Please log in to access RBAC management features.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {error && (
            <div className="flex items-center space-x-2 text-sm text-red-600 bg-red-50 p-2 rounded">
              <IconComponent name="AlertCircle" className="h-4 w-4" />
              <span>{error}</span>
            </div>
          )}

          <div className="space-y-2">
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              type="text"
              placeholder="Enter username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLogin()}
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              placeholder="Enter password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLogin()}
            />
          </div>

          <div className="flex justify-end space-x-2 pt-4">
            <Button
              variant="outline"
              onClick={() => onOpenChange(false)}
              disabled={loading}
            >
              Cancel
            </Button>
            <Button onClick={handleLogin} disabled={loading}>
              {loading ? (
                <>
                  <IconComponent
                    name="Loader2"
                    className="h-4 w-4 mr-2 animate-spin"
                  />
                  Logging in...
                </>
              ) : (
                <>
                  <IconComponent name="LogIn" className="h-4 w-4 mr-2" />
                  Log In
                </>
              )}
            </Button>
          </div>

          <div className="text-xs text-muted-foreground text-center pt-2">
            Default credentials: langflow / langflow
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
