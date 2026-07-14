import "./globals.css";
import type { ReactNode } from "react";

export const metadata = {
  title: "ScopeHarbor — Local AppSec Audit Platform",
  description: "Local-first defensive web application security audits for explicitly authorized targets"
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var saved=localStorage.getItem('scopeharbor-theme');var theme=saved==='light'||saved==='dark'?saved:(matchMedia('(prefers-color-scheme: light)').matches?'light':'dark');document.documentElement.dataset.theme=theme;document.documentElement.style.colorScheme=theme;}catch(e){document.documentElement.dataset.theme='dark';}})();`
          }}
        />
      </head>
      <body>{children}</body>
    </html>
  );
}
