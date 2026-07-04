// spectrIDA Desktop — Electron main process.
// Boots the local Python backend (uvicorn), waits for it to answer, then loads
// the renderer. Kills the backend on quit. Provides a native "open binary" dialog.

const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const { spawn } = require("child_process");
const path = require("path");
const http = require("http");

const BACKEND_PORT = 8737;
const BACKEND_URL = `http://127.0.0.1:${BACKEND_PORT}`;
// Repo layout: desktop/ sits next to spectrida/. phantomrt lives beside the repo
// (or is pip-installed). Add both to PYTHONPATH so the backend imports resolve.
const REPO_ROOT = path.resolve(__dirname, "..");
const PHANTOM_ROOT = "C:\\Users\\Administrator\\project_atlas";

let backend = null;
let win = null;

function pythonExe() {
  return process.env.SPECTRIDA_PYTHON ||
    "C:\\Users\\Administrator\\AppData\\Local\\Programs\\Python\\Python312\\python.exe";
}

function startBackend() {
  const env = Object.assign({}, process.env, {
    PYTHONPATH: `${REPO_ROOT};${PHANTOM_ROOT}`,
    PYTHONUNBUFFERED: "1",
  });
  backend = spawn(pythonExe(),
    ["-m", "uvicorn", "desktop.backend.server:app",
      "--host", "127.0.0.1", "--port", String(BACKEND_PORT), "--log-level", "warning"],
    { cwd: REPO_ROOT, env });
  backend.stdout.on("data", d => process.stdout.write(`[backend] ${d}`));
  backend.stderr.on("data", d => process.stderr.write(`[backend] ${d}`));
  backend.on("exit", code => console.log(`[backend] exited ${code}`));
}

function waitForBackend(tries = 60) {
  return new Promise((resolve, reject) => {
    const attempt = n => {
      http.get(`${BACKEND_URL}/health`, res => {
        res.resume();
        resolve();
      }).on("error", () => {
        if (n <= 0) return reject(new Error("backend never came up"));
        setTimeout(() => attempt(n - 1), 500);
      });
    };
    attempt(tries);
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1500, height: 940, minWidth: 1100, minHeight: 680,
    backgroundColor: "#08090e",
    titleBarStyle: "hiddenInset",
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, "renderer", "index.html"));
}

ipcMain.handle("backend-url", () => BACKEND_URL);

ipcMain.handle("pick-binary", async () => {
  const r = await dialog.showOpenDialog(win, {
    title: "Choose a binary to index",
    properties: ["openFile"],
    filters: [
      { name: "Binaries", extensions: ["exe", "dll", "so", "nso", "bin", "elf", "o", "dylib"] },
      { name: "All files", extensions: ["*"] },
    ],
  });
  return r.canceled ? null : r.filePaths[0];
});

function isBackendUp() {
  return new Promise((resolve) => {
    const req = http.get(`${BACKEND_URL}/health`, (res) => { res.resume(); resolve(true); });
    req.on("error", () => resolve(false));
    req.setTimeout(800, () => { req.destroy(); resolve(false); });
  });
}

// Only one instance — a second `npm start` just focuses the existing window
// instead of spawning a rival backend that fights for the port (the thing that
// jammed launches during testing).
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    if (win) { if (win.isMinimized()) win.restore(); win.show(); win.focus(); }
  });
}

app.whenReady().then(async () => {
  // Reuse a backend that's already alive (e.g. left from a previous run) instead
  // of spawning a second one that would fail to bind the port.
  if (await isBackendUp()) {
    console.log("[backend] already running — reusing");
  } else {
    startBackend();
  }
  createWindow();
  try {
    await waitForBackend();
    win.webContents.send("backend-ready");
  } catch (e) {
    console.error(e);
  }
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

function killBackend() {
  if (backend && !backend.killed) {
    try { backend.kill(); } catch (_) {}
    backend = null;
  }
}

app.on("window-all-closed", () => { killBackend(); if (process.platform !== "darwin") app.quit(); });
app.on("before-quit", killBackend);
app.on("quit", killBackend);
