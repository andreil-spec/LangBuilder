// BulkAssignmentPanel - Placeholder for bulk assignment capabilities

import IconComponent from "@/components/common/genericIconComponent";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";

interface BulkAssignmentPanelProps {
  // Future props for bulk operations
}

export default function BulkAssignmentPanel({}: BulkAssignmentPanelProps) {
  return (
    <Card>
      <CardContent className="p-6 text-center text-gray-500">
        <IconComponent name="Users" className="h-8 w-8 mx-auto mb-2" />
        <p>Bulk assignment capabilities coming soon...</p>
        <p className="text-sm mt-1">
          Assign roles to multiple users/groups simultaneously
        </p>
      </CardContent>
    </Card>
  );
}
