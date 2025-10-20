const { app, BrowserWindow, protocol } = require('electron')
const path = require('path')
const fs = require('fs')
const openpgp = require('openpgp')
const fetch = require('node-fetch')

let mainWindow

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1000,
    height: 800,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true
    }
  })
  mainWindow.loadFile('index.html')
}

app.whenReady().then(() => {
  // register httpe protocol handler inside the app
  protocol.registerBufferProtocol('httpe', async (request, respond) => {
    try {
      // parse URL
      const url = new URL(request.url)
      // determine keys directory: env KEYS_DIR > ../keys > ./keys
      let keysDir = process.env.KEYS_DIR || path.resolve(__dirname, '..', 'keys')
      if (!fs.existsSync(keysDir)) {
        const alt = path.resolve(__dirname, 'keys')
        if (fs.existsSync(alt)) keysDir = alt
      }
      console.log('Using keys directory:', keysDir)
      const clientPrivPath = path.join(keysDir, 'client_priv.asc')
      const serverPubPath = path.join(keysDir, 'server_pub.asc')

      // prepare variables to hold key material; prefer file contents if present
      let serverPub = null
      let clientPriv = null
      if (fs.existsSync(serverPubPath)) {
        serverPub = fs.readFileSync(serverPubPath, 'utf8')
      }
      if (fs.existsSync(clientPrivPath)) {
        clientPriv = fs.readFileSync(clientPrivPath, 'utf8')
      }

      // If server public key missing, attempt to fetch from the target server
      async function tryFetchServerPub(hostname) {
        const tries = [
          `http://${hostname}:533/keys/server_pub.asc`,
          `http://${hostname}:533/.well-known/httpe/server_pub.asc`,
          `http://${hostname}:553/keys/server_pub.asc`,
          `http://${hostname}:553/.well-known/httpe/server_pub.asc`
        ]
        for (const urlTry of tries) {
          try {
            const r = await fetch(urlTry)
            if (r.ok) {
              const txt = await r.text()
              if (txt && txt.includes('BEGIN PGP PUBLIC KEY BLOCK')) return txt
            }
          } catch (e) {
            // ignore and try next
          }
        }
        return null
      }

      const ciphertext = request.uploadData && request.uploadData[0] ? request.uploadData[0].bytes : null

      // if no ciphertext, we will send a simple GET-like request as plaintext
      // For demo: GET -> send empty PGy message
      // In practice, you'd build encrypted request similar to the server's expectations

      // For demo purposes, create a plaintext and encrypt it to serverPub
      let body = ''
      if (ciphertext) body = Buffer.from(ciphertext).toString()
      else body = ''

      // ensure server public key available: file or remote fetch
      if (!serverPub) {
        serverPub = await tryFetchServerPub(url.hostname)
        if (!serverPub && fs.existsSync(serverPubPath)) {
          serverPub = fs.readFileSync(serverPubPath, 'utf8')
        }
      }
      if (!serverPub) {
        respond({ mimeType: 'text/plain', data: Buffer.from('Error: server public key not found in keys directory and could not be fetched from the server.') })
        return
      }
      const serverKey = await openpgp.readKey({ armoredKey: serverPub })

      // ensure client private key available
      if (!clientPriv) {
        if (fs.existsSync(clientPrivPath)) clientPriv = fs.readFileSync(clientPrivPath, 'utf8')
      }
      if (!clientPriv) {
        respond({ mimeType: 'text/plain', data: Buffer.from('Error: client private key not found in keys directory.') })
        return
      }
      let priv = await openpgp.readPrivateKey({ armoredKey: clientPriv })

      // Try to decrypt the private key. Support multiple attempts with user prompt.
      const passfile = path.join(keysDir, 'passphrase.txt')
      let pass = ''
      if (process.env.PGP_PASSPHRASE) {
        pass = process.env.PGP_PASSPHRASE
      } else if (fs.existsSync(passfile)) {
        pass = fs.readFileSync(passfile, 'utf8').trim()
      }

      let decryptedPriv = priv
      let decrypted = false
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          // Try decrypting (if pass is empty and key is unencrypted this may still succeed or throw)
          decryptedPriv = await openpgp.decryptKey({ privateKey: decryptedPriv, passphrase: pass })
          decrypted = true
          break
        } catch (err) {
          // If decryption failed and we can prompt, ask the user for a passphrase
          try {
            if (mainWindow && mainWindow.webContents) {
              const prompt = attempt === 0 ? 'Enter PGP passphrase (empty for none):' : 'Passphrase incorrect, try again:'
              // prompt returns null if user cancelled
              const userPass = await mainWindow.webContents.executeJavaScript(`window.prompt(${JSON.stringify(prompt)}, "")`)
              if (typeof userPass === 'string' && userPass !== '') {
                pass = userPass
                // reload priv from armored string so we decrypt fresh
                decryptedPriv = await openpgp.readPrivateKey({ armoredKey: clientPriv })
                continue
              }
            }
          } catch (e) {
            // ignore prompt errors
          }
          // no prompt or user cancelled; try next attempt (may retry with same pass or exit)
        }
      }

      if (!decrypted) {
        // final attempt: if pass was empty, try decrypt with empty string once more
        try {
          decryptedPriv = await openpgp.decryptKey({ privateKey: decryptedPriv, passphrase: '' })
          decrypted = true
        } catch (err) {
          respond({ mimeType: 'text/plain', data: Buffer.from('Error: Signing key is not decrypted. Provide correct passphrase via prompt, PGP_PASSPHRASE env var, or keys/passphrase.txt.') })
          return
        }
      }

      // use decryptedPriv for signing
      priv = decryptedPriv

      // Ensure private key is decrypted before using for signing
      if (priv.isDecrypted === false || (typeof priv.isDecrypted === 'undefined' && priv.getKeys && priv.getKeys()[0] && priv.getKeys()[0].isEncrypted)) {
        respond({ mimeType: 'text/plain', data: Buffer.from('Error: Signing key is not decrypted. Put passphrase in keys/passphrase.txt or provide a decrypted private key.') })
        return
      }

      const encrypted = await openpgp.encrypt({
        message: await openpgp.createMessage({ text: body }),
        encryptionKeys: serverKey,
        signingKeys: priv,
        format: 'binary'
      })

      // post to server over http on port 533 by convention
      const target = `http://${url.hostname}:533${url.pathname}${url.search}`
      const res = await fetch(target, { method: 'POST', body: Buffer.from(encrypted), headers: { 'Content-Type': 'application/httpe+pgp' } })
      const data = await res.arrayBuffer()
      // Try to decrypt the response using our client private key and return plaintext to the renderer
      try {
        const decryptedMsg = await openpgp.readMessage({ binaryMessage: new Uint8Array(data) })
        const plainResult = await openpgp.decrypt({ message: decryptedMsg, decryptionKeys: priv })
        const plainText = plainResult.data
        const sigHeader = res.headers.get('HTTPE-Signature') || ''
        // If plaintext looks like HTML, set text/html, otherwise text/plain
        const isHTML = /<\/?[a-z][\s\S]*>/i.test(plainText)
        respond({ mimeType: isHTML ? 'text/html' : 'text/plain', data: Buffer.from(plainText), headers: { 'HTTPE-Signature': sigHeader } })
      } catch (e) {
        // If decryption fails, return original binary with an error header
        respond({ mimeType: 'application/httpe+pgp', data: Buffer.from(data), headers: { 'X-HTTPE-Error': e.toString() } })
      }
    } catch (e) {
      respond({ mimeType: 'text/plain', data: Buffer.from(e.toString()) })
    }
  })

  createWindow()
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit()
})
