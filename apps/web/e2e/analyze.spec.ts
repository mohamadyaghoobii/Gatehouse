import { expect, test } from "@playwright/test";

test.describe("Gatehouse analyze flow", () => {
  test("homepage loads with the analyzer", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Analyze pipeline" })).toBeVisible();
    await expect(page.getByRole("button", { name: /Analyze pipeline/ })).toBeVisible();
  });

  test("analyzing the starter risky pipeline shows a score and findings", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /Analyze pipeline/ }).click();

    await expect(page.locator(".ring .score-num")).toBeVisible();
    const score = Number(await page.locator(".ring .score-num").innerText());
    expect(score).toBeLessThan(80);

    await expect(page.getByRole("heading", { name: "Findings" })).toBeVisible();
    await expect(page.locator(".finding").first()).toBeVisible();
    await expect(page.locator(".sev-legend")).toContainText("Critical");
  });

  test("hardened workflow scores higher than the risky starter", async ({ page }) => {
    await page.goto("/");

    await page.getByRole("button", { name: /Analyze pipeline/ }).click();
    await expect(page.locator(".ring .score-num")).toBeVisible();
    const riskyScore = Number(await page.locator(".ring .score-num").innerText());

    await page.locator(".editor-toolbar select").selectOption({ label: "Hardened GitHub Actions pipeline" });
    await page.getByRole("button", { name: /Analyze pipeline/ }).click();
    await expect(page.locator(".score-meta .grade")).toContainText(/A|B/);
    const hardenedScore = Number(await page.locator(".ring .score-num").innerText());

    expect(hardenedScore).toBeGreaterThan(riskyScore);
  });

  test("a GitLab sample analyzes and reports findings", async ({ page }) => {
    await page.goto("/");
    await page.locator(".editor-toolbar select").selectOption({ label: "Risky GitLab CI container deploy" });
    await page.getByRole("button", { name: /Analyze pipeline/ }).click();
    await expect(page.locator(".finding").first()).toBeVisible();
    await expect(page.locator(".metric")).toContainText(/Gitlab|GitLab/i);
  });

  test("remediation snippet is shown and copyable", async ({ page }) => {
    await page.goto("/");
    await page.getByRole("button", { name: /Analyze pipeline/ }).click();
    await expect(page.locator(".finding").first()).toBeVisible();
    await expect(page.locator(".finding").first().getByText("Remediation")).toBeVisible();
  });

  test("rules catalog page renders rules", async ({ page }) => {
    await page.goto("/rules");
    await expect(page.getByRole("heading", { name: "Rules" })).toBeVisible();
    await expect(page.locator(".rule-row").first()).toBeVisible();
  });
});
