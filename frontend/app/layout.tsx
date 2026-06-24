import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Sidebar } from "@/components/sidebar";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "CBAD Pipeline Dashboard",
  description: "Unified security posture across the 9-stage CBAD DevSecOps pipeline",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={`dark ${inter.variable}`}>
      <body className="font-sans bg-slate-950 text-white antialiased">
        <div className="flex min-h-screen">
          <Sidebar />
          <main className="flex-1 px-8 py-7 max-w-[1480px]">{children}</main>
        </div>
      </body>
    </html>
  );
}
