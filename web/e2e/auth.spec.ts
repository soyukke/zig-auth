import { test, expect } from '@playwright/test';

test.describe('Authentication Pages', () => {
  test('register page renders', async ({ page }) => {
    await page.goto('/register');
    await expect(page.locator('h1')).toContainText('Register');
    await expect(page.locator('input#username')).toBeVisible();
    await expect(page.locator('button[type="submit"]')).toContainText('Passkey');
  });

  test('login page renders', async ({ page }) => {
    await page.goto('/login');
    await expect(page.locator('h1')).toContainText('Login');
    await expect(page.locator('button').first()).toContainText('Passkey');
  });

  test('register page links to login', async ({ page }) => {
    await page.goto('/register');
    await page.click('a[href="/login"]');
    await expect(page).toHaveURL(/\/login/);
  });

  test('login page links to register', async ({ page }) => {
    await page.goto('/login');
    await page.click('a[href="/register"]');
    await expect(page).toHaveURL(/\/register/);
  });

  test('register button disabled without username', async ({ page }) => {
    await page.goto('/register');
    const btn = page.locator('button[type="submit"]');
    await expect(btn).toBeDisabled();
  });
});
