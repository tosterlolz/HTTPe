package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/term"
)

func main() {
	var keysDir string
	var port int
	flag.StringVar(&keysDir, "keys", "", "directory to load PGP keys from (overrides relative paths)")
	flag.IntVar(&port, "port", 553, "server port to send requests to (default 553)")
	flag.Parse()
	if keysDir != "" {
		os.Setenv("KEYS_DIR", keysDir)
	}

	clientEntity := loadEntity(resolveKeyPath("../keys/client_priv.asc"))
	serverEntity := loadEntity(resolveKeyPath("../keys/server_pub.asc"))

	// Dane do wysłania
	// Data to send
	message := []byte(`{"note": "secret data from client"}`)

	// Zaszyfruj wiadomość do serwera
	// Encrypt the message to the server
	var enc bytes.Buffer
	wb, err := openpgp.Encrypt(&enc, openpgp.EntityList{serverEntity}, clientEntity, nil, nil)
	if err != nil {
		panic(err)
	}
	wb.Write(message)
	wb.Close()

	// Wyślij request
	req, _ := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/", port), &enc)
	req.Header.Set("Content-Type", "application/httpe+pgp")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	cipherResp, _ := io.ReadAll(resp.Body)

	// Decrypt the response
	md, err := openpgp.ReadMessage(bytes.NewReader(cipherResp), openpgp.EntityList{clientEntity}, nil, nil)
	if err != nil {
		panic(err)
	}
	plaintext, _ := io.ReadAll(md.UnverifiedBody)
	fmt.Println("[Client] Decrypted response:", string(plaintext))

	// Check the server's signature
	sig := resp.Header.Get("HTTPE-Signature")
	if sig != "" {
		fmt.Println("[Client] Server signature:\n", sig)
	} else {
		fmt.Println("[WARN] No signature in header")
	}
}

func loadEntity(path string) *openpgp.Entity {
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	entityList, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		panic(err)
	}
	e := entityList[0]

	// If the private key is encrypted, try to decrypt it using the passphrase
	pass := getCachedPassphrase()
	if e.PrivateKey != nil && e.PrivateKey.Encrypted {
		if pass != "" {
			if err := e.PrivateKey.Decrypt([]byte(pass)); err != nil {
				panic(fmt.Errorf("failed to decrypt private key %s: %w", path, err))
			}
		} else {
			// Try empty passphrase first, then fail with an actionable message
			if err := e.PrivateKey.Decrypt([]byte("")); err != nil {
				panic(fmt.Errorf("private key %s is encrypted; set PGP_PASSPHRASE environment variable to the passphrase: %w", path, err))
			}
		}
	}

	for _, sub := range e.Subkeys {
		if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
			if pass != "" {
				if err := sub.PrivateKey.Decrypt([]byte(pass)); err != nil {
					panic(fmt.Errorf("failed to decrypt subkey in %s: %w", path, err))
				}
			} else {
				if err := sub.PrivateKey.Decrypt([]byte("")); err != nil {
					panic(fmt.Errorf("encrypted subkey in %s; set PGP_PASSPHRASE environment variable: %w", path, err))
				}
			}
		}
	}

	return e
}

// resolveKeyPath tries the given path first, then looks in KEYS_DIR, then next to the executable.
func resolveKeyPath(p string) string {
	if _, err := os.Stat(p); err == nil {
		return p
	}
	if kd := os.Getenv("KEYS_DIR"); kd != "" {
		alt := filepath.Join(kd, filepath.Base(p))
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	if exe, err := os.Executable(); err == nil {
		alt := filepath.Join(filepath.Dir(exe), p)
		if _, err := os.Stat(alt); err == nil {
			return alt
		}
	}
	return p
}

var cachedPass string
var passLoaded bool

func getCachedPassphrase() string {
	if passLoaded {
		return cachedPass
	}
	if env := os.Getenv("PGP_PASSPHRASE"); env != "" {
		cachedPass = env
		passLoaded = true
		return cachedPass
	}
	fmt.Print("Enter PGP passphrase (empty for none): ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err == nil {
		cachedPass = strings.TrimSpace(string(pw))
	} else {
		cachedPass = ""
	}
	passLoaded = true
	return cachedPass
}
