import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "Defensive AppSec Audit",
  description: "Local-first defensive web application security audit platform"
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
