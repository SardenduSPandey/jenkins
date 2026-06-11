import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

test('test', async ({ page }) => {
  await page.goto('https://example.com/login');
  await page.getByRole('textbox', { name: 'Email' }).click();
  await page.getByRole('textbox', { name: 'Email' }).fill('user@example.com');
  await page.getByRole('textbox', { name: 'Password' }).click();
  await page.getByRole('textbox', { name: 'Password' }).fill('Password123!');
  await page.getByRole('button', { name: 'Log In' }).click();
  
  const authFilePath = path.join(__dirname, 'auth.json');
  await page.context().storageState({ path: authFilePath });
  console.log("✅ Session saved to auth.json");
  
  // Check if auth.json file was created
  if (fs.existsSync(authFilePath)) {
    console.log(`✅ File verified at: ${authFilePath}`);
    const stats = fs.statSync(authFilePath);
    console.log(`📁 File size: ${stats.size} bytes`);
  } else {
    console.error(`❌ File NOT found at: ${authFilePath}`);
    throw new Error(`Auth file was not created at ${authFilePath}`);
  }
  
  // Extract cookies for ZAP/Burp
  const cookies = await page.context().cookies();
  console.log("Cookies:", cookies);
  await page.context().browser()?.close();
});