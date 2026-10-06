import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "공개 소개와 나만의 패스키 공간",
  description: "공개 소개는 누구나, 개인 공간은 패스키로.",
  other: {
    "codex-preview": "development",
  },
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
    <html lang="ko">
      <body className="antialiased">{children}</body>
    </html>
  );
}
