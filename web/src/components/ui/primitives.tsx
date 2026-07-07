import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "../../lib/utils";

const buttonVariants = cva(
  "inline-flex h-9 items-center justify-center gap-2 whitespace-nowrap rounded-md border px-3 text-sm font-semibold transition-colors focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary:
          "border-[var(--om-gold)] bg-[var(--om-gold)] text-[var(--om-bg)] hover:bg-[color-mix(in_srgb,var(--om-gold)_85%,black)] focus-visible:outline-[var(--om-focus)]",
        secondary:
          "border-[var(--om-border)] bg-[var(--om-surface)] text-[var(--om-text-bright)] hover:bg-[var(--om-surface-elevated)] focus-visible:outline-[var(--om-focus)]",
        ghost:
          "border-transparent bg-transparent text-[var(--om-text)] hover:bg-[var(--om-surface-elevated)] focus-visible:outline-[var(--om-focus)]"
      }
    },
    defaultVariants: {
      variant: "secondary"
    }
  }
);

type ButtonProps = React.ButtonHTMLAttributes<HTMLButtonElement> &
  VariantProps<typeof buttonVariants>;

export function Button({ className, variant, ...props }: ButtonProps): React.ReactElement {
  return <button className={cn(buttonVariants({ variant }), className)} {...props} />;
}

// Tones map onto the Carved Light accent tokens rather than raw Tailwind
// colors. The accents are mid-tone with a translucent fill, so a badge reads on
// both the near-black operator surfaces and any lighter fallback surface.
const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-1 text-xs font-semibold",
  {
    variants: {
      tone: {
        neutral: "border-[var(--om-border)] bg-[var(--om-surface-muted)] text-[var(--om-text)]",
        ok: "border-[color-mix(in_srgb,var(--om-sage)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-sage)_14%,transparent)] text-[var(--om-sage)]",
        warn: "border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_14%,transparent)] text-[var(--om-copper)]",
        off: "border-[var(--om-border)] bg-transparent text-[var(--om-text-muted)]",
        info: "border-[color-mix(in_srgb,var(--om-gold)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-gold)_14%,transparent)] text-[var(--om-gold)]"
      }
    },
    defaultVariants: {
      tone: "neutral"
    }
  }
);

type BadgeProps = React.HTMLAttributes<HTMLSpanElement> &
  VariantProps<typeof badgeVariants>;

export function Badge({ className, tone, ...props }: BadgeProps): React.ReactElement {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}

export function Surface({
  className,
  ...props
}: React.HTMLAttributes<HTMLElement>): React.ReactElement {
  return (
    <section
      className={cn("rounded-lg border border-[var(--om-border)] bg-[var(--om-surface)] shadow-sm", className)}
      {...props}
    />
  );
}
