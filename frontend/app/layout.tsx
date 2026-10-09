import type { Metadata, Viewport } from "next";
import "./globals.css";
import { AuthProvider } from "@/lib/auth";
import { ToastProvider } from "@/components/ui";

export const metadata: Metadata = {
  title: "Malware Scan — Security Operations",
  description: "Malware Scan: malware & ransomware scanning, EDR-style monitoring, FIM, vulnerability and configuration assessment, and automated response.",
  robots: { index: false, follow: false },
};

export const viewport: Viewport = { themeColor: "#03060d", colorScheme: "dark" };

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <a href="#main" className="sr-only">Skip to content</a>
        <AuthProvider>
          <ToastProvider>{children}</ToastProvider>
        </AuthProvider>
      </body>
    </html>
  );
}
