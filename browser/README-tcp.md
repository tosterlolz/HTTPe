HTTPE local TCP protocol

This project includes a small local-only TCP protocol to keep the server's HTML and API off the clear web.

- Server listens by default on 127.0.0.1:5533 (configurable via `HTTPE_TCP_PORT` env var).
- Electron client will connect to the local TCP server when loading `httpe://localhost:...` URLs.

To start server with TCP enabled (example):

```powershell
$env:PGP_PASSPHRASE='your-passphrase'
cd server
go run . --port 533 --keys .\.well-known\httpe\
```

If you need to change the TCP address, set `HTTPE_TCP_PORT` in the server `.env` or environment.
