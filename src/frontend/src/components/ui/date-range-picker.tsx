import * as React from "react";
import IconComponent from "@/components/common/genericIconComponent";
import { Button } from "@/components/ui/button";
import { Calendar } from "@/components/ui/calendar";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { cn } from "@/utils/utils";

interface DateRange {
  from: Date | undefined;
  to: Date | undefined;
}

interface DatePickerWithRangeProps
  extends React.HTMLAttributes<HTMLDivElement> {
  date: DateRange | undefined;
  onDateChange: (date: DateRange | undefined) => void;
}

export function DatePickerWithRange({
  className,
  date,
  onDateChange,
}: DatePickerWithRangeProps) {
  return (
    <div className={cn("grid gap-2", className)}>
      <Popover>
        <PopoverTrigger asChild>
          <Button
            id="date"
            variant={"outline"}
            className={cn(
              "w-[300px] justify-start text-left font-normal",
              !date && "text-muted-foreground",
            )}
          >
            <IconComponent name="Calendar" className="mr-2 h-4 w-4" />
            {date?.from ? (
              date.to ? (
                <>
                  {date.from.toLocaleDateString()} -{" "}
                  {date.to.toLocaleDateString()}
                </>
              ) : (
                date.from.toLocaleDateString()
              )
            ) : (
              <span>Pick a date range</span>
            )}
          </Button>
        </PopoverTrigger>
        <PopoverContent className="w-auto p-0" align="start">
          <div className="p-4">
            <div className="text-sm text-muted-foreground mb-2">
              Range picker functionality not yet implemented
            </div>
            <Calendar
              mode="single"
              selected={date?.from}
              onSelect={(selectedDate) => {
                if (selectedDate instanceof Date) {
                  onDateChange({ from: selectedDate, to: selectedDate });
                } else {
                  onDateChange(undefined);
                }
              }}
            />
          </div>
        </PopoverContent>
      </Popover>
    </div>
  );
}
