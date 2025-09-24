import React from "react";

interface CalendarProps {
  mode?: "single" | "multiple";
  selected?: Date | Date[];
  onSelect?: (date: Date | Date[] | undefined) => void;
  disabled?: (date: Date) => boolean;
  className?: string;
}

export function Calendar({
  mode = "single",
  selected,
  onSelect,
  disabled,
  className,
}: CalendarProps) {
  const today = new Date();
  const currentMonth = today.getMonth();
  const currentYear = today.getFullYear();

  const handleDateClick = (date: Date) => {
    if (disabled && disabled(date)) return;
    if (onSelect) {
      onSelect(date);
    }
  };

  // Simple calendar implementation
  const daysInMonth = new Date(currentYear, currentMonth + 1, 0).getDate();
  const firstDayOfMonth = new Date(currentYear, currentMonth, 1).getDay();

  const days: React.ReactElement[] = [];

  // Empty cells for days before month starts
  for (let i = 0; i < firstDayOfMonth; i++) {
    days.push(<div key={`empty-${i}`} className="p-2"></div>);
  }

  // Days of the month
  for (let day = 1; day <= daysInMonth; day++) {
    const date = new Date(currentYear, currentMonth, day);
    const isSelected =
      mode === "single" &&
      selected instanceof Date &&
      date.toDateString() === selected.toDateString();
    const isDisabled = disabled && disabled(date);

    days.push(
      <button
        key={day}
        onClick={() => handleDateClick(date)}
        disabled={isDisabled}
        className={`
          p-2 text-sm rounded hover:bg-gray-100 disabled:opacity-50 disabled:cursor-not-allowed
          ${isSelected ? "bg-blue-500 text-white" : ""}
          ${isDisabled ? "opacity-50 cursor-not-allowed" : "cursor-pointer"}
        `}
      >
        {day}
      </button>,
    );
  }

  return (
    <div className={`p-4 border rounded-lg bg-white ${className || ""}`}>
      <div className="text-center font-medium mb-4">
        {today.toLocaleDateString("en-US", { month: "long", year: "numeric" })}
      </div>
      <div className="grid grid-cols-7 gap-1">
        {["Su", "Mo", "Tu", "We", "Th", "Fr", "Sa"].map((day) => (
          <div
            key={day}
            className="p-2 text-xs font-medium text-center text-gray-500"
          >
            {day}
          </div>
        ))}
        {days}
      </div>
    </div>
  );
}
