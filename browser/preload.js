const { contextBridge } = require('electron')

contextBridge.exposeInMainWorld('electron', {
  // future APIs
})
