// ConflictDetectionPanel - Detects and resolves role assignment conflicts
import { useState } from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import type { ConflictDetection } from "./index";

interface ConflictDetectionPanelProps {
  conflicts: ConflictDetection[];
  onResolve: () => void;
}

export default function ConflictDetectionPanel({
  conflicts,
  onResolve,
}: ConflictDetectionPanelProps) {
  const [isExpanded, setIsExpanded] = useState(true);
  const [resolvedConflicts, setResolvedConflicts] = useState<Set<number>>(
    new Set(),
  );

  // Group conflicts by severity
  const errorConflicts = conflicts.filter((c) => c.severity === "error");
  const warningConflicts = conflicts.filter((c) => c.severity === "warning");

  // Handle conflict resolution
  const handleResolveConflict = (conflictIndex: number) => {
    setResolvedConflicts((prev) => new Set(prev).add(conflictIndex));
  };

  // Get conflict icon
  const getConflictIcon = (type: ConflictDetection["type"]) => {
    switch (type) {
      case "duplicate":
        return "Copy";
      case "override":
        return "AlertTriangle";
      case "inheritance_conflict":
        return "GitBranch";
      default:
        return "AlertCircle";
    }
  };

  // Get conflict severity styling
  const getConflictStyling = (severity: ConflictDetection["severity"]) => {
    return severity === "error"
      ? {
          borderColor: "border-red-300",
          bgColor: "bg-red-50",
          textColor: "text-red-800",
          badgeVariant: "destructive" as const,
        }
      : {
          borderColor: "border-yellow-300",
          bgColor: "bg-yellow-50",
          textColor: "text-yellow-800",
          badgeVariant: "secondary" as const,
        };
  };

  if (conflicts.length === 0) {
    return (
      <Card className="border-green-200 bg-green-50">
        <CardContent className="p-4">
          <div className="flex items-center space-x-2 text-green-800">
            <IconComponent name="CheckCircle" className="h-5 w-5" />
            <span className="font-medium">No Conflicts Detected</span>
          </div>
          <p className="text-sm text-green-700 mt-1">
            This role assignment appears to be conflict-free and safe to
            proceed.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card
      className={`${errorConflicts.length > 0 ? "border-red-300" : "border-yellow-300"}`}
    >
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <IconComponent
              name={errorConflicts.length > 0 ? "AlertTriangle" : "AlertCircle"}
              className={`h-5 w-5 ${errorConflicts.length > 0 ? "text-red-600" : "text-yellow-600"}`}
            />
            <span>Conflict Detection</span>
            <Badge
              variant={errorConflicts.length > 0 ? "destructive" : "secondary"}
              className="text-xs"
            >
              {conflicts.length} conflict{conflicts.length !== 1 ? "s" : ""}
            </Badge>
          </div>

          <Collapsible open={isExpanded} onOpenChange={setIsExpanded}>
            <CollapsibleTrigger asChild>
              <button className="text-gray-400 hover:text-gray-600">
                <IconComponent
                  name={isExpanded ? "ChevronUp" : "ChevronDown"}
                  className="h-4 w-4"
                />
              </button>
            </CollapsibleTrigger>
          </Collapsible>
        </CardTitle>
        <CardDescription>
          {errorConflicts.length > 0
            ? "Critical conflicts must be resolved before proceeding"
            : "Warning conflicts should be reviewed but don't block assignment"}
        </CardDescription>
      </CardHeader>

      <CollapsibleContent>
        <CardContent className="space-y-4">
          {/* Error Conflicts */}
          {errorConflicts.length > 0 && (
            <div className="space-y-3">
              <h4 className="font-medium text-red-800 flex items-center">
                <IconComponent name="XCircle" className="h-4 w-4 mr-2" />
                Critical Errors ({errorConflicts.length})
              </h4>

              {errorConflicts.map((conflict, index) => {
                const styling = getConflictStyling(conflict.severity);
                const globalIndex = conflicts.indexOf(conflict);
                const isResolved = resolvedConflicts.has(globalIndex);

                return (
                  <Alert
                    key={globalIndex}
                    className={`${styling.borderColor} ${styling.bgColor}`}
                  >
                    <div className="flex items-start space-x-3">
                      <IconComponent
                        name={getConflictIcon(conflict.type) as any}
                        className={`h-5 w-5 mt-0.5 ${styling.textColor}`}
                      />

                      <div className="flex-1 min-w-0">
                        <AlertTitle
                          className={`${styling.textColor} flex items-center space-x-2`}
                        >
                          <span className="capitalize">
                            {conflict.type.replace("_", " ")}
                          </span>
                          <Badge
                            variant={styling.badgeVariant}
                            className="text-xs"
                          >
                            {conflict.severity}
                          </Badge>
                          {isResolved && (
                            <Badge variant="secondary" className="text-xs">
                              Resolved
                            </Badge>
                          )}
                        </AlertTitle>

                        <AlertDescription className={styling.textColor}>
                          {conflict.message}
                        </AlertDescription>

                        {/* Suggestions */}
                        {conflict.suggestions.length > 0 && (
                          <div className="mt-3 space-y-2">
                            <p
                              className={`text-sm font-medium ${styling.textColor}`}
                            >
                              Suggested Solutions:
                            </p>
                            <ul
                              className={`text-sm ${styling.textColor} space-y-1`}
                            >
                              {conflict.suggestions.map(
                                (suggestion, suggIndex) => (
                                  <li
                                    key={suggIndex}
                                    className="flex items-start space-x-2"
                                  >
                                    <IconComponent
                                      name="ArrowRight"
                                      className="h-3 w-3 mt-0.5 flex-shrink-0"
                                    />
                                    <span>{suggestion}</span>
                                  </li>
                                ),
                              )}
                            </ul>
                          </div>
                        )}

                        {/* Resolution Actions */}
                        <div className="mt-3 flex items-center space-x-2">
                          {!isResolved ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleResolveConflict(globalIndex)}
                              className="text-xs"
                            >
                              <IconComponent
                                name="Check"
                                className="h-3 w-3 mr-1"
                              />
                              Mark as Resolved
                            </Button>
                          ) : (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() =>
                                setResolvedConflicts((prev) => {
                                  const newSet = new Set(prev);
                                  newSet.delete(globalIndex);
                                  return newSet;
                                })
                              }
                              className="text-xs"
                            >
                              <IconComponent
                                name="Undo"
                                className="h-3 w-3 mr-1"
                              />
                              Unresolve
                            </Button>
                          )}

                          <Button size="sm" variant="ghost" className="text-xs">
                            <IconComponent
                              name="HelpCircle"
                              className="h-3 w-3 mr-1"
                            />
                            Get Help
                          </Button>
                        </div>
                      </div>
                    </div>
                  </Alert>
                );
              })}
            </div>
          )}

          {/* Warning Conflicts */}
          {warningConflicts.length > 0 && (
            <div className="space-y-3">
              <h4 className="font-medium text-yellow-800 flex items-center">
                <IconComponent name="AlertCircle" className="h-4 w-4 mr-2" />
                Warnings ({warningConflicts.length})
              </h4>

              {warningConflicts.map((conflict, index) => {
                const styling = getConflictStyling(conflict.severity);
                const globalIndex = conflicts.indexOf(conflict);
                const isResolved = resolvedConflicts.has(globalIndex);

                return (
                  <Alert
                    key={globalIndex}
                    className={`${styling.borderColor} ${styling.bgColor}`}
                  >
                    <div className="flex items-start space-x-3">
                      <IconComponent
                        name={getConflictIcon(conflict.type) as any}
                        className={`h-5 w-5 mt-0.5 ${styling.textColor}`}
                      />

                      <div className="flex-1 min-w-0">
                        <AlertTitle
                          className={`${styling.textColor} flex items-center space-x-2`}
                        >
                          <span className="capitalize">
                            {conflict.type.replace("_", " ")}
                          </span>
                          <Badge
                            variant={styling.badgeVariant}
                            className="text-xs"
                          >
                            {conflict.severity}
                          </Badge>
                          {isResolved && (
                            <Badge variant="secondary" className="text-xs">
                              Acknowledged
                            </Badge>
                          )}
                        </AlertTitle>

                        <AlertDescription className={styling.textColor}>
                          {conflict.message}
                        </AlertDescription>

                        {/* Suggestions */}
                        {conflict.suggestions.length > 0 && (
                          <div className="mt-3 space-y-2">
                            <p
                              className={`text-sm font-medium ${styling.textColor}`}
                            >
                              Recommendations:
                            </p>
                            <ul
                              className={`text-sm ${styling.textColor} space-y-1`}
                            >
                              {conflict.suggestions.map(
                                (suggestion, suggIndex) => (
                                  <li
                                    key={suggIndex}
                                    className="flex items-start space-x-2"
                                  >
                                    <IconComponent
                                      name="ArrowRight"
                                      className="h-3 w-3 mt-0.5 flex-shrink-0"
                                    />
                                    <span>{suggestion}</span>
                                  </li>
                                ),
                              )}
                            </ul>
                          </div>
                        )}

                        {/* Acknowledgment Actions */}
                        <div className="mt-3 flex items-center space-x-2">
                          {!isResolved ? (
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleResolveConflict(globalIndex)}
                              className="text-xs"
                            >
                              <IconComponent
                                name="Eye"
                                className="h-3 w-3 mr-1"
                              />
                              Acknowledge
                            </Button>
                          ) : (
                            <span className="text-sm text-yellow-700 flex items-center">
                              <IconComponent
                                name="CheckCircle"
                                className="h-4 w-4 mr-1"
                              />
                              Acknowledged
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </Alert>
                );
              })}
            </div>
          )}

          {/* Resolution Summary */}
          <div className="border-t pt-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4 text-sm">
                <div className="flex items-center space-x-1">
                  <IconComponent
                    name="AlertTriangle"
                    className="h-4 w-4 text-red-500"
                  />
                  <span>Errors: {errorConflicts.length}</span>
                  <span className="text-gray-500">
                    (
                    {
                      errorConflicts.filter((_, i) =>
                        resolvedConflicts.has(
                          conflicts.indexOf(errorConflicts[i]),
                        ),
                      ).length
                    }{" "}
                    resolved)
                  </span>
                </div>

                <div className="flex items-center space-x-1">
                  <IconComponent
                    name="AlertCircle"
                    className="h-4 w-4 text-yellow-500"
                  />
                  <span>Warnings: {warningConflicts.length}</span>
                  <span className="text-gray-500">
                    (
                    {
                      warningConflicts.filter((_, i) =>
                        resolvedConflicts.has(
                          conflicts.indexOf(warningConflicts[i]),
                        ),
                      ).length
                    }{" "}
                    acknowledged)
                  </span>
                </div>
              </div>

              <Button
                size="sm"
                variant="outline"
                onClick={onResolve}
                className="text-xs"
              >
                <IconComponent name="RefreshCw" className="h-3 w-3 mr-1" />
                Re-check Conflicts
              </Button>
            </div>

            {/* Blocking Status */}
            {errorConflicts.length > 0 && (
              <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded">
                <div className="flex items-center space-x-2 text-red-800">
                  <IconComponent name="Lock" className="h-4 w-4" />
                  <span className="font-medium">Assignment Blocked</span>
                </div>
                <p className="text-sm text-red-700 mt-1">
                  {
                    errorConflicts.filter(
                      (_, i) =>
                        !resolvedConflicts.has(
                          conflicts.indexOf(errorConflicts[i]),
                        ),
                    ).length
                  }{" "}
                  critical error(s) must be resolved before proceeding.
                </p>
              </div>
            )}
          </div>
        </CardContent>
      </CollapsibleContent>
    </Card>
  );
}
