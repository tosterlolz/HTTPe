package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
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
	flag.IntVar(&port, "port", 553, "port to listen on (default 553)")
	flag.Parse()
	if keysDir != "" {
		os.Setenv("KEYS_DIR", keysDir)
	}

	http.HandleFunc("/", handleHTTPE)
	fmt.Printf("HTTPE server listening on :%d\n", port)
	http.ListenAndServe(fmt.Sprintf(":%d", port), nil)
}

func handleHTTPE(w http.ResponseWriter, r *http.Request) {
	// Load server (private) key
	serverEntity := loadEntity(resolveKeyPath("../keys/server_priv.asc"))

	// Load client (public) key - try local file first, then attempt to fetch from the client host and cache it
	clientKeyPath := resolveKeyPath("../keys/client_pub.asc")
	clientEntity, err := loadPublicEntity(clientKeyPath)
	if err != nil {
		// try to fetch from remote host
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		if host == "" {
			host = r.RemoteAddr
		}
		fetched, ferr := fetchAndCacheClientPub(host, clientKeyPath)
		if ferr != nil {
			http.Error(w, "client public key not found locally and fetch failed: "+ferr.Error(), http.StatusBadGateway)
			return
		}
		clientEntity = fetched
	}

	// Read the encrypted request body
	ciphertext, _ := io.ReadAll(r.Body)
	defer r.Body.Close()

	md, err := openpgp.ReadMessage(bytes.NewReader(ciphertext), openpgp.EntityList{serverEntity}, nil, nil)
	if err != nil {
		http.Error(w, "Decryption error: "+err.Error(), 400)
		return
	}

	plaintext, _ := io.ReadAll(md.UnverifiedBody)
	fmt.Println("[Server] Decrypted content:", string(plaintext))

	// Verify the signature
	if md.SignatureError != nil {
		fmt.Println("[WARN] Signature error:", md.SignatureError)
	} else if md.SignedBy != nil {
		// md.SignedBy is a *openpgp.Key; print signer key id and fingerprint (if available)
		if md.SignedBy.PublicKey != nil {
			fmt.Printf("[OK] Signed by key id: %X, fingerprint: %X\n", md.SignedBy.PublicKey.KeyId, md.SignedBy.PublicKey.Fingerprint)
		} else {
			fmt.Println("[OK] Signed by key (no public key available)")
		}
	} else {
		fmt.Println("[WARN] No signature")
	}

	// Prepare the response
	response := []byte(fmt.Sprintf("%s", string(plaintext)))

	var out bytes.Buffer
	err = openpgp.ArmoredDetachSign(&out, serverEntity, bytes.NewReader(response), nil)
	if err != nil {
		http.Error(w, "Signing error: "+err.Error(), 500)
		return
	}
	sig := out.String()

	// Encrypt the response for the client
	var enc bytes.Buffer
	wb, _ := openpgp.Encrypt(&enc, openpgp.EntityList{clientEntity}, serverEntity, nil, nil)
	wb.Write(response)
	wb.Close()

	w.Header().Set("Content-Type", "application/httpe+pgp")
	w.Header().Set("HTTPE-Signature", sig)
	w.Write(enc.Bytes())
}

// loadPublicEntity reads an armored public key from path and returns the entity, or error
func loadPublicEntity(path string) (*openpgp.Entity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	list, err := openpgp.ReadArmoredKeyRing(f)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("no entity in keyring")
	}
	return list[0], nil
}

// fetchAndCacheClientPub attempts to fetch the client's public key from several well-known URLs
// and writes it to destPath if successful. Returns the parsed entity.
func fetchAndCacheClientPub(host, destPath string) (*openpgp.Entity, error) {
	tries := []string{
		fmt.Sprintf("http://%s:533/keys/client_pub.asc", host),
		fmt.Sprintf("http://%s:533/.well-known/httpe/client_pub.asc", host),
		fmt.Sprintf("http://%s:553/keys/client_pub.asc", host),
		fmt.Sprintf("http://%s:553/.well-known/httpe/client_pub.asc", host),
	}
	var lastErr error
	for _, u := range tries {
		resp, err := http.Get(u)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			lastErr = fmt.Errorf("%s: status %d", u, resp.StatusCode)
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		txt := string(body)
		if !strings.Contains(txt, "BEGIN PGP PUBLIC KEY BLOCK") {
			lastErr = fmt.Errorf("%s: no public key block", u)
			continue
		}
		// ensure dest directory exists
		_ = os.MkdirAll(filepath.Dir(destPath), 0o755)
		if err := os.WriteFile(destPath, body, 0o644); err != nil {
			// not fatal; still try to parse in memory
			fmt.Println("[WARN] Failed to cache fetched key:", err)
		}
		// parse
		eList, err := openpgp.ReadArmoredKeyRing(strings.NewReader(txt))
		if err != nil {
			lastErr = err
			continue
		}
		if len(eList) == 0 {
			lastErr = fmt.Errorf("no entity parsed from %s", u)
			continue
		}
		return eList[0], nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no urls to try")
	}
	return nil, lastErr
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

	pass := getCachedPassphrase()
	if e.PrivateKey != nil && e.PrivateKey.Encrypted {
		if pass != "" {
			if err := e.PrivateKey.Decrypt([]byte(pass)); err != nil {
				panic(fmt.Errorf("failed to decrypt private key %s: %w", path, err))
			}
		} else {
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
	// fallback to original path (will cause the original error)
	return p
}

var cachedPass string
var passLoaded bool

func getCachedPassphrase() string {
	if passLoaded {
		return cachedPass
	}
	// prefer env var
	if env := os.Getenv("PGP_PASSPHRASE"); env != "" {
		cachedPass = env
		passLoaded = true
		return cachedPass
	}
	// interactive prompt
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
