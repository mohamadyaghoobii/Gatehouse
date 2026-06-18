import "./styles.css";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Gatehouse",
  description: "CI/CD pipeline review for DevOps and DevSecOps teams"
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
