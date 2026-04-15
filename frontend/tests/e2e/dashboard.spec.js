import { test, expect } from "@playwright/test";

const nowIso = new Date().toISOString();

const sampleAuditRows = [
  {
    id: 1,
    timestamp: nowIso,
    session_id: "sess-e2e-1",
    agent_id: "test-agent",
    action: "calculator",
    status: "executed",
    input_text: "2+2",
    output_text: "4",
  },
];

const sampleSecurityRows = [
  {
    id: 1,
    session_id: "sess-e2e-1",
    event_type: "PROMPT_EVAL",
    risk_score: 0.12,
    details: { reason: "Safe prompt" },
    timestamp: nowIso,
  },
];

test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("aegis_api_key", "test-key");
  });

  await page.route("**/api/logs/security*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(sampleSecurityRows),
    });
  });

  await page.route("**/api/logs/audit*", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(sampleAuditRows),
    });
  });

  await page.route("**/api/agent/execute", async (route) => {
    const requestBody = route.request().postDataJSON();
    const simulationMode = Boolean(requestBody?.dry_run);
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        session_id: "sess-e2e-2",
        firewall: {
          status: "safe",
          decision: "allow",
          is_blocked: false,
          risk_score: 0.11,
          matched_rules: [],
          threats: [],
        },
        explainability: {
          risk_score: 0.11,
          risk_percent: 11,
          zone: "safe",
          safe_zone_max_percent: 60,
          block_zone_min_percent: 60,
          matched_rules: [],
          threats: [],
        },
        gateway: {
          status: simulationMode ? "simulated" : "executed",
          allowed: true,
          simulation: simulationMode,
          reason: simulationMode ? "Simulation shows prompt can pass firewall checks." : "Execution completed.",
          agent_thought: simulationMode ? "Dry run mode active." : "Safe path selected.",
          agent_response: simulationMode ? "Simulation complete." : "Execution completed.",
        },
      }),
    });
  });
});

test("logs tab renders rows and supports search filter", async ({ page }) => {
  await page.goto("/");

  await page.getByRole("button", { name: /logs/i }).click();
  await expect(page.getByText("Audit Log Stream")).toBeVisible();
  await expect(page.getByText("calculator")).toBeVisible();

  const search = page.getByPlaceholder("Search action, prompt, response, session, agent...");
  await search.fill("does-not-match");
  await expect(page.getByText("No audit records match the current filters.")).toBeVisible();
});

test("dashboard execute flow shows safe decision", async ({ page }) => {
  await page.goto("/");

  await page.getByPlaceholder("Paste Master API Key...").fill("test-key");
  await page
    .getByPlaceholder("Enter a prompt (e.g., 'Search for latest AI news' or 'IGNORE PREVIOUS INSTRUCTIONS')...")
    .fill("Calculate 2+2");
  await page.getByRole("button", { name: /^Execute$/ }).click();

  await expect(page.getByText("PROMPT SAFE")).toBeVisible();
  await expect(page.getByText("Decision: Allowed and executed", { exact: true })).toBeVisible();
});

test("dry run simulation shows mode and zone", async ({ page }) => {
  await page.goto("/");

  await page.getByLabel(/Dry Run Simulator/i).check();
  await page
    .getByPlaceholder("Enter a prompt (e.g., 'Search for latest AI news' or 'IGNORE PREVIOUS INSTRUCTIONS')...")
    .fill("Summarize AI safety basics");
  await page.getByRole("button", { name: /^Simulate$/ }).click();

  await expect(page.getByText("Mode: Simulation", { exact: true })).toBeVisible();
  await expect(page.getByText("Zone: Safe Zone (0-60%)", { exact: true })).toBeVisible();
});
