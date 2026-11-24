process.env.NODE_ENV = 'test';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { Builder, By, until } = require('selenium-webdriver');
const chrome = require('selenium-webdriver/chrome');
const { defaultReporter, openReport } = require('../scripts/generate-selenium-report');

// Configuration
const DEFAULT_PORT = 3001;
let baseUrl = process.env.APP_URL || process.env.BASE_URL || `http://localhost:${DEFAULT_PORT}`;
let localServer = null;
let driver = null;

const isHeadless = process.env.HEADLESS !== 'false';
const FINAL_TEST_NAME = 'Authenticated user can view dashboard, user profile badge, and scan history UI';

/**
 * Creates a shared Chrome WebDriver instance using Selenium Manager.
 * Configured with headless mode by default for Jenkins/CI, or normal visible Chrome
 * with maximized window and detached session when HEADLESS=false.
 * Preserves required flags for container and CI compatibility.
 */
async function createDriver() {
  console.log(`Selenium running in ${isHeadless ? 'HEADLESS' : 'VISIBLE'} mode`);

  const options = new chrome.Options();
  if (isHeadless) {
    options.addArguments('--headless=new');
  } else {
    options.addArguments('--start-maximized');
    if (typeof options.detachDriver === 'function') {
      options.detachDriver(true);
    }
  }
  options.addArguments('--no-sandbox');
  options.addArguments('--disable-dev-shm-usage');
  options.addArguments('--disable-gpu');
  options.addArguments('--window-size=1280,800');

  const driverInstance = await new Builder()
    .forBrowser('chrome')
    .setChromeOptions(options)
    .build();

  // Set implicit wait timeout
  await driverInstance.manage().setTimeouts({ implicit: 5000 });
  return driverInstance;
}

/**
 * Pauses execution for 3 seconds only in visible mode so the page can be viewed after each test.
 */
async function pauseIfVisible() {
  if (!isHeadless) {
    await new Promise((resolve) => setTimeout(resolve, 3000));
  }
}

test.before(async () => {
  // Check if live application (e.g. Docker Compose on port 3001 or standalone on 3000) is reachable
  let serverReachable = false;
  const candidateUrls = [baseUrl, 'http://localhost:3001', 'http://localhost:3000'];

  for (const url of candidateUrls) {
    try {
      const res = await fetch(`${url}/api/health`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) {
        baseUrl = url;
        serverReachable = true;
        break;
      }
    } catch (_) {}
  }

  // If no external server is running, spin up an ephemeral local Express instance
  if (!serverReachable) {
    const app = require('../server');
    localServer = http.createServer(app);
    await new Promise((resolve) => localServer.listen(0, '127.0.0.1', resolve));
    const port = localServer.address().port;
    baseUrl = `http://127.0.0.1:${port}`;
  }

  // Initialize single shared WebDriver instance for entire test suite
  driver = await createDriver();
});

test.after(async () => {
  // Generate professional HTML report and open in default browser
  try {
    const reportPath = defaultReporter.saveReport('reports/selenium-report.html', {
      isHeadless,
      baseUrl
    });
    openReport(reportPath);
  } catch (err) {
    console.error('[Report] Error generating report:', err.message);
  }

  if (driver) {
    try {
      if (isHeadless) {
        // Headless mode for CI/Jenkins: send W3C QUIT command to close Chrome and session
        await driver.quit();
      } else {
        // Visible mode: do NOT send driver.quit() (W3C DELETE /session), which causes
        // ChromeDriver to close all browser windows. Instead, stop the ChromeDriver
        // process directly via driver.onQuit_(). Combined with options.detachDriver(true),
        // this stops the ChromeDriver background service and allows the Node process to exit,
        // leaving the detached Chrome window open for the user to view and manually close.
        if (typeof driver.onQuit_ === 'function') {
          await driver.onQuit_();
        }
      }
    } catch (_) {}
  }
  if (localServer) {
    await new Promise((resolve) => localServer.close(resolve));
  }
});

test.beforeEach(async (t) => {
  defaultReporter.recordStart(t);
  if (driver) {
    try {
      await driver.manage().deleteAllCookies();
    } catch (_) {}
  }
});

test.afterEach(async (t) => {
  defaultReporter.recordEnd(t);
  // Pause for 3 seconds and clear cookies only after tests 1-4
  if (!t || t.name !== FINAL_TEST_NAME) {
    await pauseIfVisible();
    if (driver) {
      try {
        await driver.manage().deleteAllCookies();
      } catch (_) {}
    }
  }
});

// ---------------------------------------------------------------------------
// Selenium Browser Automation (E2E) Test Suite
// ---------------------------------------------------------------------------

test('Login page loads successfully in a fresh browser session', async () => {
  await driver.get(`${baseUrl}/login`);

  // Verify page title
  const title = await driver.getTitle();
  assert.ok(title.includes('CloudSec'), `Title should contain CloudSec, got "${title}"`);
  assert.ok(title.includes('Sign In'), `Title should contain Sign In, got "${title}"`);

  // Verify main card heading
  const heading = await driver.findElement(By.css('h1'));
  const headingText = await heading.getText();
  assert.equal(headingText, 'Sign in to CloudSec');

  // Verify defensive platform eyebrow label
  const eyebrow = await driver.findElement(By.css('.eyebrow'));
  const eyebrowText = await eyebrow.getText();
  assert.ok(eyebrowText.includes('DEFENSIVE CLOUD SECURITY PLATFORM'));

  // Verify current URL
  const currentUrl = await driver.getCurrentUrl();
  assert.ok(currentUrl.includes('/login'), `URL should contain /login, got "${currentUrl}"`);
});

test('Continue with Google button is visible, displayed, and points to /auth/google', async () => {
  await driver.get(`${baseUrl}/login`);

  // Locate the Google Sign-In button
  const googleBtn = await driver.findElement(By.id('googleBtn'));
  assert.ok(googleBtn, 'Google button element with id "googleBtn" must exist');

  // Verify button is visible and displayed on screen
  const isDisplayed = await googleBtn.isDisplayed();
  assert.equal(isDisplayed, true, 'Continue with Google button must be visible');

  // Verify button text
  const btnText = await googleBtn.getText();
  assert.ok(btnText.includes('Continue with Google'), `Button text should be "Continue with Google", got "${btnText}"`);

  // Verify button points to the correct Google OAuth route
  const href = await googleBtn.getAttribute('href');
  assert.ok(href, 'Button must have href attribute');
  assert.ok(href.endsWith('/auth/google'), `Button href should end with /auth/google, got "${href}"`);

  // Verify accessible role and label
  const role = await googleBtn.getAttribute('role');
  assert.equal(role, 'button');
  const ariaLabel = await googleBtn.getAttribute('aria-label');
  assert.equal(ariaLabel, 'Continue with Google');
});

test('Unauthenticated navigation to dashboard (/) redirects browser to /login', async () => {
  // Navigate to root path without session cookie
  await driver.get(`${baseUrl}/`);

  // Wait until URL redirects to /login
  await driver.wait(until.urlContains('/login'), 5000);

  const redirectedUrl = await driver.getCurrentUrl();
  assert.ok(redirectedUrl.includes('/login'), `Redirected URL must contain /login, got "${redirectedUrl}"`);

  // Confirm login card is displayed after redirect
  const loginCard = await driver.findElement(By.css('.login-card'));
  assert.equal(await loginCard.isDisplayed(), true, 'Login card must be visible after redirect');
});

test('Login page displays security badges and platform capabilities', async () => {
  await driver.get(`${baseUrl}/login`);

  // Verify security badges are present and visible
  const badges = await driver.findElement(By.css('.security-badges'));
  assert.equal(await badges.isDisplayed(), true);
  const badgeText = await badges.getText();
  assert.ok(badgeText.includes('OAuth 2.0'));
  assert.ok(badgeText.includes('CSRF State Protection'));
  assert.ok(badgeText.includes('HttpOnly Session'));

  // Verify platform capability highlights
  const features = await driver.findElement(By.css('.platform-features'));
  assert.equal(await features.isDisplayed(), true);
  const featureText = await features.getText();
  assert.ok(featureText.includes('8 Automated Detection Rules'));
});

test(FINAL_TEST_NAME, async () => {
  // Start an ephemeral test instance with NODE_ENV=test so /auth/test-session is enabled
  const app = require('../server');
  const testServer = http.createServer(app);
  await new Promise((resolve) => testServer.listen(0, '127.0.0.1', resolve));
  const testPort = testServer.address().port;
  const testAppUrl = `http://127.0.0.1:${testPort}`;

  try {
    // 1. Create authenticated session via test helper endpoint
    const sessionRes = await fetch(`${testAppUrl}/auth/test-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        user: {
          id: 'selenium-auditor-id',
          googleId: 'g-selenium-12345',
          email: 'selenium.auditor@cloudsec.local',
          name: 'Selenium Security Auditor',
          picture: ''
        }
      })
    });
    assert.equal(sessionRes.status, 200);
    const cookieHeader = sessionRes.headers.get('set-cookie');
    assert.ok(cookieHeader && cookieHeader.includes('cloudsec.sid'));
    const sidMatch = cookieHeader.match(/cloudsec\.sid=([^;]+)/);
    const sidValue = sidMatch ? sidMatch[1] : '';

    // 2. Open Chrome, navigate to domain, inject cookie, and load dashboard (/)
    await driver.get(`${testAppUrl}/login`);
    await driver.manage().addCookie({
      name: 'cloudsec.sid',
      value: sidValue,
      path: '/'
    });

    await driver.get(`${testAppUrl}/`);

    // 3. Verify dashboard loads with correct title and authenticated user name
    const title = await driver.getTitle();
    assert.ok(title.includes('CloudSec'), `Title should contain CloudSec, got "${title}"`);

    const userProfile = await driver.findElement(By.id('userProfile'));
    await driver.wait(until.elementIsVisible(userProfile), 5000);
    const userNameEl = await driver.findElement(By.id('userName'));
    const userNameText = await userNameEl.getText();
    assert.equal(userNameText, 'Selenium Security Auditor');

    // 4. Verify Scan History section and Refresh button are present and visible
    const historySection = await driver.findElement(By.id('historySection'));
    assert.equal(await historySection.isDisplayed(), true, 'History section must be visible');

    const refreshBtn = await driver.findElement(By.id('refreshHistoryBtn'));
    assert.equal(await refreshBtn.isDisplayed(), true, 'Refresh history button must be visible');
  } finally {
    await new Promise((resolve) => testServer.close(resolve));
  }
});
