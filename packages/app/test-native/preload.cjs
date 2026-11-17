// This bridge is confined to the native test fixture. It never reads or receives credentials.
const { contextBridge, ipcRenderer } = require("electron");
contextBridge.exposeInMainWorld("rippleNative", {
  sandboxed: process.sandboxed === true,
  contextIsolated: process.contextIsolated === true,
  probe: () => ipcRenderer.invoke("ripple-native:probe"),
});
