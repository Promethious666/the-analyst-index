import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "The Analyst Index — choose security tools with context",
  description: "A transparent, evidence-led directory for choosing open-source security tools.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
