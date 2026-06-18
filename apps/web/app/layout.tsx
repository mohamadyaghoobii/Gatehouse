import "./styles.css";
import type { Metadata } from "next";
import { Sidebar } from "../components/Sidebar";

export const metadata: Metadata = {
  title: "Gatehouse — CI/CD pipeline review",
  description:
    "Review GitHub Actions, GitLab CI, and Jenkins pipelines for risky permissions, secret exposure, supply chain risk, and weak deployment gates."
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <div className="shell">
          <Sidebar />
          <main className="main">{children}</main>
        </div>
      </body>
    </html>
  );
}
