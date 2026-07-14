import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "ScopeHarbor — Local AppSec Audit Platform",
  description: "Local-first defensive web application security audits for explicitly authorized targets"
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
