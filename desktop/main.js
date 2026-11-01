const { app, BrowserWindow, Tray, Menu, Notification, dialog, nativeImage, session, ipcMain } = require('electron');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

let window;
let tray;
let backend;
let notificationTimer;
let lastNotifiedEventId = 0;
let notificationsInitialized = false;
const backendUrl = 'http://127.0.0.1:8080';
const startupSettingsPath = path.join(app.getPath('userData'), 'settings.json');

function appIcon() {
  const iconPath = path.join(__dirname, 'tray-icon.ico');
  const icon = nativeImage.createFromPath(iconPath);
  if (icon.isEmpty()) {
    throw new Error(`The Morpheus application icon is missing or invalid:\n${iconPath}`);
  }
  return icon;
}

function getStartupPreference() {
  try {
    const settings = JSON.parse(fs.readFileSync(startupSettingsPath, 'utf8'));
    return typeof settings.openAtLogin === 'boolean' ? settings.openAtLogin : null;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

function setStartupPreference(enabled) {
  app.setLoginItemSettings({ openAtLogin: enabled });
  fs.mkdirSync(path.dirname(startupSettingsPath), { recursive: true });
  fs.writeFileSync(startupSettingsPath, JSON.stringify({ openAtLogin: enabled }, null, 2));
}

function openWindow() {
  if (!window || window.isDestroyed()) return;
  if (window.isMinimized()) window.restore();
  window.show();
  window.focus();
}

function backendExecutable() {
  if (app.isPackaged) {
    return path.join(process.resourcesPath, 'backend', 'morpheus-backend.exe');
  }
  return path.join(app.getAppPath(), '.venv', 'Scripts', 'python.exe');
}

async function startBackend() {
  const executable = backendExecutable();
  if (!fs.existsSync(executable)) {
    throw new Error(
      `The Morpheus backend is missing:\n${executable}\n\n` +
      'Reinstall Morpheus using the complete installer. For development, create .venv and install requirements.txt.'
    );
  }

  const userData = app.getPath('userData');
  const configPath = path.join(userData, 'config.json');
  const dataPath = path.join(userData, 'data');
  const logPath = path.join(userData, 'backend.log');
  fs.mkdirSync(dataPath, { recursive: true });
  if (!fs.existsSync(configPath)) {
    const defaultConfig = app.isPackaged
      ? path.join(process.resourcesPath, 'config.default.json')
      : path.join(app.getAppPath(), 'config.json');
    if (!fs.existsSync(defaultConfig)) {
      throw new Error(`The default Morpheus configuration is missing:\n${defaultConfig}`);
    }
    fs.copyFileSync(defaultConfig, configPath);
  }

  const args = app.isPackaged
    ? ['--host', '127.0.0.1', '--port', '8080']
    : ['-m', 'uvicorn', 'morpheus.main:app', '--host', '127.0.0.1', '--port', '8080'];
  const cwd = app.isPackaged ? userData : app.getAppPath();
  const logFile = fs.openSync(logPath, 'a');
  backend = spawn(executable, args, {
    cwd,
    env: {
      ...process.env,
      MORPHEUS_DATA_DIR: dataPath,
      MORPHEUS_CONFIG_PATH: configPath,
    },
    stdio: ['ignore', logFile, logFile],
    windowsHide: true,
  });

  await new Promise((resolve, reject) => {
    backend.once('spawn', () => {
      fs.closeSync(logFile);
      resolve();
    });
    backend.once('error', error => {
      fs.closeSync(logFile);
      reject(error);
    });
    backend.once('exit', (code, signal) => {
      if (code !== 0 && !app.isQuitting) {
        console.error(`Morpheus backend exited (code=${code}, signal=${signal || 'none'}).`);
      }
    });
  });
}

async function waitForBackend() {
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const result = await fetch(`${backendUrl}/api/status`);
      if (result.ok) return true;
    } catch {}
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  return false;
}

async function createWindow() {
  window = new BrowserWindow({
    width: 1320,
    height: 860,
    minWidth: 900,
    minHeight: 650,
    title: 'Morpheus Defense',
    icon: appIcon(),
    autoHideMenuBar: true,
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js'),
    },
    backgroundColor: '#07111f',
  });
  window.setMenuBarVisibility(false);
  window.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    if (input.key === 'F11') {
      event.preventDefault();
      window.setFullScreen(!window.isFullScreen());
    } else if (input.key === 'Escape' && window.isFullScreen()) {
      event.preventDefault();
      window.setFullScreen(false);
    }
  });
  const notifyFullScreenChange = () => {
    if (!window.isDestroyed()) window.webContents.send('morpheus:fullscreen-changed', window.isFullScreen());
  };
  window.on('enter-full-screen', notifyFullScreenChange);
  window.on('leave-full-screen', notifyFullScreenChange);
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', (event, url) => {
    if (url !== backendUrl && !url.startsWith(`${backendUrl}/`)) event.preventDefault();
  });
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({ responseHeaders: {
      ...details.responseHeaders,
      'Content-Security-Policy': ["default-src 'self'; connect-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"],
      'X-Content-Type-Options': ['nosniff'],
      'Referrer-Policy': ['no-referrer'],
    } });
  });
  await window.loadURL(backendUrl);
  window.on('close', event => {
    if (!app.isQuitting) {
      event.preventDefault();
      window.hide();
    }
  });
}

function startFirewallServiceWithElevation() {
  if (process.platform !== 'win32') {
    return Promise.reject(new Error('The firewall service can only be started on Windows.'));
  }
  const command = [
    "$ErrorActionPreference = 'Stop'",
    "$sc = Join-Path $env:WINDIR 'System32\\sc.exe'",
    "$process = Start-Process -FilePath $sc -ArgumentList @('start', 'MorpheusFirewallWorker') -Verb RunAs -Wait -PassThru",
    'exit $process.ExitCode',
  ].join('; ');
  const encoded = Buffer.from(command, 'utf16le').toString('base64');

  return new Promise((resolve, reject) => {
    const child = spawn('powershell.exe', [
      '-NoProfile',
      '-NonInteractive',
      '-EncodedCommand',
      encoded,
    ], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('Timed out waiting for Windows service approval or startup.'));
    }, 120000);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', error => {
      clearTimeout(timer);
      reject(new Error(`Could not request administrator approval: ${error.message}`));
    });
    child.once('close', code => {
      clearTimeout(timer);
      if (code === 0) {
        resolve({ started: true });
        return;
      }
      const detail = (stderr || stdout).trim();
      reject(new Error(detail || `Windows could not start the firewall service (exit code ${code}).`));
    });
  });
}

async function notifyNewQuarantines() {
  try {
    const response = await fetch(`${backendUrl}/api/events?limit=200`);
    if (!response.ok) return;
    const events = await response.json();
    if (!notificationsInitialized) {
      if (events.length) lastNotifiedEventId = Math.max(...events.map(event => event.id));
      notificationsInitialized = true;
      return;
    }
    const pending = events
      .filter(event => event.id > lastNotifiedEventId && event.kind === 'download_suspicious' && typeof event.response === 'string' && event.response.startsWith('quarantined:'))
      .sort((left, right) => left.id - right.id);
    if (events.length) lastNotifiedEventId = Math.max(lastNotifiedEventId, ...events.map(event => event.id));
    for (const event of pending) {
      if (Notification.isSupported()) {
        new Notification({
          title: 'Morpheus quarantined a suspicious download',
          body: `${event.target} was isolated for review. Open Morpheus to view the detection.`,
        }).show();
      }
    }
  } catch {
    // The local service may not be ready during startup or shutdown.
  }
}

app.whenReady().then(() => {
  Menu.setApplicationMenu(null);
  ipcMain.handle('morpheus:select-folder', async () => {
    if (!window) return null;
    const result = await dialog.showOpenDialog(window, { properties: ['openDirectory'] });
    return result.canceled ? null : result.filePaths[0] || null;
  });
  ipcMain.handle('morpheus:select-download-folder', async () => {
    if (!window) return null;
    const result = await dialog.showOpenDialog(window, {
      title: 'Choose folder to monitor for downloads',
      buttonLabel: 'Use this folder',
      properties: ['openDirectory'],
    });
    return result.canceled ? null : result.filePaths[0] || null;
  });
  ipcMain.handle('morpheus:select-file', async () => {
    if (!window) return null;
    const result = await dialog.showOpenDialog(window, { properties: ['openFile'] });
    return result.canceled ? null : result.filePaths[0] || null;
  });
  ipcMain.handle('morpheus:start-firewall-service', startFirewallServiceWithElevation);
  ipcMain.handle('morpheus:toggle-fullscreen', () => {
    if (!window || window.isDestroyed()) throw new Error('The Morpheus window is unavailable.');
    window.setFullScreen(!window.isFullScreen());
    return window.isFullScreen();
  });
  (async () => {
    try {
      if (process.platform === 'win32') {
        const startupPreference = getStartupPreference();
        setStartupPreference(startupPreference === null ? true : startupPreference);
      }
      await startBackend();
      if (!await waitForBackend()) {
        throw new Error(
          `The Morpheus backend did not become ready.\n\n` +
          `Check the backend log for details:\n${path.join(app.getPath('userData'), 'backend.log')}\n\n` +
          'If the problem continues, reinstall Morpheus using the complete installer.'
        );
      }
      await createWindow();
      notifyNewQuarantines();
      notificationTimer = setInterval(notifyNewQuarantines, 10000);
      const trayIcon = appIcon();
      tray = new Tray(trayIcon);
      tray.setToolTip('Morpheus Defense');
      tray.on('click', openWindow);
      tray.setContextMenu(Menu.buildFromTemplate([
        { label: 'Open Morpheus', click: openWindow },
        { label: 'Check running apps', click: () => fetch(`${backendUrl}/api/scan`, { method: 'POST' }).catch(() => {}) },
        {
          label: 'Start Morpheus at Windows sign-in',
          type: 'checkbox',
          checked: process.platform === 'win32' && app.getLoginItemSettings().openAtLogin,
          enabled: process.platform === 'win32',
          click: item => {
            if (process.platform === 'win32') setStartupPreference(item.checked);
          },
        },
        { label: 'Exit', click: () => { app.isQuitting = true; app.quit(); } },
      ]));
    } catch (error) {
      dialog.showErrorBox('Morpheus could not start', error.message);
      app.quit();
    }
  })();
});

app.on('activate', openWindow);
app.on('before-quit', () => { app.isQuitting = true; });
app.on('will-quit', () => {
  if (notificationTimer) clearInterval(notificationTimer);
  if (backend && !backend.killed) backend.kill();
});
