HTTPE Browser (Electron)

This is a tiny Electron app that demonstrates a custom `httpe://` protocol handler.

Setup
1. Install dependencies (requires Node.js + npm):

```powershell
cd client/browser
npm install
```

2. Place your PGP keys (armored) into a `keys` folder next to the `client` folder, for example:
```
client/keys/client_priv.asc
client/keys/client_pub.asc
client/keys/server_priv.asc
client/keys/server_pub.asc
```

3. Start the app:

```powershell
npm start
```

Usage
- Enter a URL like `httpe://localhost/` and click Go. The app will encrypt a request and POST to `http://localhost:533/` by default and display the server response inside the iframe.

Notes
- This is a demo. It doesn't implement passphrase prompts, advanced error handling, or full browsing features.
- openpgp v5 API is used in Node and bundled in package.json.
