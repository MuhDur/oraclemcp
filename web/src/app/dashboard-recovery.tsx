import * as React from "react";
import { RefreshCcw } from "lucide-react";

import { Button } from "../components/ui/primitives";

export function QueryErrorNotice({
  title,
  error,
  retryLabel,
  retryingLabel,
  retrying = false,
  onRetry
}: {
  title: string;
  error: Error;
  retryLabel?: string;
  retryingLabel?: string;
  retrying?: boolean;
  onRetry?: () => void;
}): React.ReactElement {
  return (
    <div
      className="rounded-lg border border-[var(--om-rust)] bg-[color-mix(in_srgb,var(--om-rust)_12%,transparent)] p-4"
      role="alert"
    >
      <p className="font-semibold text-[var(--om-text-bright)]">{title}</p>
      <p className="mt-1 text-sm text-[var(--om-text-muted)]">{error.message}</p>
      {onRetry ? (
        <Button
          type="button"
          variant="secondary"
          className="mt-3"
          disabled={retrying}
          aria-busy={retrying || undefined}
          onClick={onRetry}
        >
          <RefreshCcw className={retrying ? "size-4 animate-spin" : "size-4"} aria-hidden="true" />
          {retrying ? retryingLabel ?? "Retrying" : retryLabel ?? "Retry"}
        </Button>
      ) : null}
    </div>
  );
}

export function ErrorNotice({ message }: { message: string }): React.ReactElement {
  return (
    <p
      className="m-4 rounded-md border border-[color-mix(in_srgb,var(--om-copper)_45%,transparent)] bg-[color-mix(in_srgb,var(--om-copper)_12%,transparent)] p-3 text-sm font-semibold text-[var(--om-text-bright)]"
      role="alert"
    >
      {message}
    </p>
  );
}
