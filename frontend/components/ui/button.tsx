import * as React from "react";
import { cn } from "@/lib/utils";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  fullWidth?: boolean;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, fullWidth, ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        "inline-flex items-center justify-center rounded-xl border border-white/10 bg-slate-900 px-4 py-2.5",
        "text-sm font-semibold text-white tracking-wide transition-colors duration-200",
        "hover:border-brand/50 hover:bg-slate-800 disabled:opacity-50 disabled:cursor-not-allowed",
        fullWidth && "w-full",
        className
      )}
      {...props}
    />
  )
);
Button.displayName = "Button";
