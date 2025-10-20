# HTTPe

Simple example demonstrating an HTTP-based protocol that uses OpenPGP to encrypt requests and responses and to sign messages.

Structure
- `server/` - Go HTTP server that accepts encrypted requests at `/httpe` and responds with an encrypted, signed message.
- `client/` - Go client that encrypts a JSON message, sends it to the server, and decrypts/verifies the response.
- `keys/` - (not included) PGP key files used by server and client. Expected filenames used by the code:
  - `server_priv.asc` (server private key)
  - `server_pub.asc` (server public key)
  - `client_priv.asc` (client private key)
  - `client_pub.asc` (client public key)

Run
1. Generate or place OpenPGP keys under `server/keys` and `client/keys` or adjust paths in the code.
2. Start the server:

```powershell
cd server
go run .
```

3. In another terminal, run the client:

```powershell
cd client
go run .
```

Optional: Electron HTTPE browser
- A tiny Electron app is available under `client/browser`. It registers an internal `httpe://` handler and POSTs encrypted requests to `http://host:533/` by default. See `client/browser/README.md` for setup.

Notes
- The code uses `golang.org/x/crypto/openpgp`, which is deprecated. This sample is intended for demonstration and interoperability with OpenPGP-formatted keys. For production use, consider using a maintained OpenPGP fork or a modern cryptography approach.
# HTTPe

