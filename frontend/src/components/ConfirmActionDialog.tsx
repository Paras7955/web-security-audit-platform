"use client";

import { useEffect, useRef } from "react";

import { AppIcon } from "@/components/AppIcon";

export function ConfirmActionDialog({
  eyebrow,
  title,
  description,
  note,
  confirmLabel,
  cancelLabel = "Keep current item",
  busyLabel,
  icon,
  isBusy,
  error,
  onCancel,
  onConfirm
}: {
  eyebrow: string;
  title: string;
  description: string;
  note: string;
  confirmLabel: string;
  cancelLabel?: string;
  busyLabel: string;
  icon: "trash" | "credential";
  isBusy: boolean;
  error?: string;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
  const dialogRef = useRef<HTMLDivElement>(null);
  const busyRef = useRef(isBusy);
  const cancelActionRef = useRef(onCancel);

  useEffect(() => {
    busyRef.current = isBusy;
    cancelActionRef.current = onCancel;
  }, [isBusy, onCancel]);

  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    cancelRef.current?.focus();
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busyRef.current) {
        cancelActionRef.current();
        return;
      }
      if (event.key === "Tab" && dialogRef.current) {
        const focusable = [...dialogRef.current.querySelectorAll<HTMLElement>("button:not(:disabled), [href], input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex='-1'])")];
        const first = focusable[0];
        const last = focusable.at(-1);
        if (!first || !last) return;
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("keydown", handleKeyDown);
      previousFocus?.focus();
    };
  }, []);

  return (
    <div className="modalBackdrop" role="presentation" onMouseDown={(event) => {
      if (event.currentTarget === event.target && !isBusy) {
        onCancel();
      }
    }}>
      <div ref={dialogRef} className="confirmDialog" role="dialog" aria-modal="true" aria-labelledby="confirm-action-dialog-title" aria-describedby="confirm-action-dialog-description">
        <span className="dialogIcon"><AppIcon name={icon} size={22} /></span>
        <div>
          <p className="panelKicker">{eyebrow}</p>
          <h3 id="confirm-action-dialog-title">{title}</h3>
          <p id="confirm-action-dialog-description">{description}</p>
          <div className="historyPreserved"><AppIcon name="shield" size={16} /><span>{note}</span></div>
          {error ? <p className="dialogError" role="alert">{error}</p> : null}
        </div>
        <div className="dialogActions">
          <button ref={cancelRef} type="button" className="secondaryButton" onClick={onCancel} disabled={isBusy}>{cancelLabel}</button>
          <button type="button" className="dangerButton" onClick={onConfirm} disabled={isBusy}>{isBusy ? busyLabel : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
