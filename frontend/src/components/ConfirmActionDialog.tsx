"use client";

import { useEffect, useRef } from "react";

import { AppIcon } from "@/components/AppIcon";

export function ConfirmActionDialog({
  eyebrow,
  title,
  description,
  note,
  confirmLabel,
  busyLabel,
  icon,
  isBusy,
  onCancel,
  onConfirm
}: {
  eyebrow: string;
  title: string;
  description: string;
  note: string;
  confirmLabel: string;
  busyLabel: string;
  icon: "trash" | "credential";
  isBusy: boolean;
  onCancel: () => void;
  onConfirm: () => void;
}) {
  const cancelRef = useRef<HTMLButtonElement>(null);
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
      <div className="confirmDialog" role="dialog" aria-modal="true" aria-labelledby="confirm-action-dialog-title">
        <span className="dialogIcon"><AppIcon name={icon} size={22} /></span>
        <div>
          <p className="panelKicker">{eyebrow}</p>
          <h3 id="confirm-action-dialog-title">{title}</h3>
          <p>{description}</p>
          <div className="historyPreserved"><AppIcon name="shield" size={16} /><span>{note}</span></div>
        </div>
        <div className="dialogActions">
          <button ref={cancelRef} type="button" className="secondaryButton" onClick={onCancel} disabled={isBusy}>Cancel</button>
          <button type="button" className="dangerButton" onClick={onConfirm} disabled={isBusy}>{isBusy ? busyLabel : confirmLabel}</button>
        </div>
      </div>
    </div>
  );
}
