import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  timeout: 30000,
  use: {
    baseURL: 'http://localhost:5173',
    trace: 'on-first-retry',
  },
  webServer: [
    {
      command: 'cd .. && node_modules/.bin/wrangler dev --port 8787',
      port: 8787,
      reuseExistingServer: true,
      timeout: 15000,
    },
    {
      command: 'npm run dev -- --port 5173',
      port: 5173,
      reuseExistingServer: true,
      timeout: 15000,
    },
  ],
});
