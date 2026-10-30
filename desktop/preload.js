const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('morpheus', {
  selectFile: () => ipcRenderer.invoke('morpheus:select-file'),
  selectFolder: () => ipcRenderer.invoke('morpheus:select-folder'),
  selectDownloadFolder: () => ipcRenderer.invoke('morpheus:select-download-folder'),
  startFirewallService: () => ipcRenderer.invoke('morpheus:start-firewall-service'),
  toggleFullScreen: () => ipcRenderer.invoke('morpheus:toggle-fullscreen'),
  onFullScreenChanged: callback => {
    const listener = (_event, isFullScreen) => callback(isFullScreen);
    ipcRenderer.on('morpheus:fullscreen-changed', listener);
    return () => ipcRenderer.removeListener('morpheus:fullscreen-changed', listener);
  },
});
