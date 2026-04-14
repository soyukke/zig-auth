import { test, expect } from '@playwright/test';

const testEmail = `test-${Date.now()}@example.com`;
const testPassword = 'testpassword123';

test.describe('Authentication Flow', () => {
  test('signup page renders', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('h1')).toContainText('Sign Up');
    await expect(page.locator('input#email')).toBeVisible();
    await expect(page.locator('input#password')).toBeVisible();
  });

  test('login page renders', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h1')).toContainText('Login');
  });

  test('signup → login → dashboard → logout', async ({ page }) => {
    // Signup
    await page.goto('/signup');
    // Wait for hydration by checking that the button is interactive
    const submitBtn = page.locator('button[type="submit"]');
    await expect(submitBtn).toBeEnabled();

    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.fill('#confirm', testPassword);
    await submitBtn.click();

    // Wait for navigation (either /login or /login?registered=true)
    await expect(page).toHaveURL(/\/login/, { timeout: 15000 });

    // Login
    await expect(page.locator('button[type="submit"]')).toBeEnabled();
    await page.fill('#email', testEmail);
    await page.fill('#password', testPassword);
    await page.locator('button[type="submit"]').click();

    // Should redirect to dashboard
    await expect(page).toHaveURL(/\/dashboard/, { timeout: 15000 });
    await expect(page.locator('h1')).toContainText('Dashboard');
    await expect(page.getByText(testEmail).first()).toBeVisible();

    // Logout
    await page.getByText('Logout').click();
    await expect(page).toHaveURL(/\/login/, { timeout: 10000 });
  });

  test('login with wrong password shows error', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('button[type="submit"]')).toBeEnabled();
    await page.fill('#email', 'nonexistent@example.com');
    await page.fill('#password', 'wrongpassword');
    await page.locator('button[type="submit"]').click();

    await expect(page.getByText('Invalid credentials')).toBeVisible({ timeout: 10000 });
  });

  test('signup with mismatched passwords shows error', async ({ page }) => {
    await page.goto('/signup');
    await expect(page.locator('button[type="submit"]')).toBeEnabled();
    await page.fill('#email', 'mismatch@example.com');
    await page.fill('#password', 'password123');
    await page.fill('#confirm', 'different456');
    await page.locator('button[type="submit"]').click();

    await expect(page.getByText('Passwords do not match')).toBeVisible({ timeout: 5000 });
  });
});
