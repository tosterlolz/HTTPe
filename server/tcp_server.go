package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/openpgp"
)

// Simple JSON-framed TCP protocol for localhost-only access.
// Client sends a single JSON line header: {method: "GET"|"POST", path: "/", body_len: N}
// For POST, the client sends exactly N bytes following the newline. Server responds with
// a single JSON line response header: {status:200, content_type: "...", length: N}
// followed by N bytes of payload.

type tcpReqHeader struct {
	Method  string `json:"method"`
	Path    string `json:"path"`
	BodyLen int    `json:"body_len"`
}

type tcpRespHeader struct {
	Status      int    `json:"status"`
	ContentType string `json:"content_type"`
	Length      int    `json:"length"`
}

func startTCPServer(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("tcp listen %s: %w", listenAddr, err)
	}
	fmt.Println("HTTPE TCP server listening on", listenAddr)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				fmt.Println("tcp accept error:", err)
				continue
			}
			go handleTCPConn(conn)
		}
	}()
	return nil
}

func handleTCPConn(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	// read header line
	line, err := r.ReadString('\n')
	if err != nil {
		return
	}
	line = strings.TrimSpace(line)
	var hdr tcpReqHeader
	if err := json.Unmarshal([]byte(line), &hdr); err != nil {
		fmt.Println("tcp: invalid header", err)
		return
	}

	// Only support GET and POST for now
	if strings.ToUpper(hdr.Method) == "GET" {
		// Only serve index.html over TCP; read file and send
		data, err := os.ReadFile("index.html")
		if err != nil {
			resp := tcpRespHeader{Status: 500, ContentType: "text/plain", Length: len(err.Error())}
			bh, _ := json.Marshal(resp)
			conn.Write(append(bh, '\n'))
			conn.Write([]byte(err.Error()))
			return
		}
		resp := tcpRespHeader{Status: 200, ContentType: "text/html; charset=utf-8", Length: len(data)}
		bh, _ := json.Marshal(resp)
		conn.Write(append(bh, '\n'))
		conn.Write(data)
		return
	}

	if strings.ToUpper(hdr.Method) == "POST" {
		// read body_len bytes
		body := make([]byte, hdr.BodyLen)
		if _, err := io.ReadFull(r, body); err != nil {
			resp := tcpRespHeader{Status: 400, ContentType: "text/plain", Length: 0}
			bh, _ := json.Marshal(resp)
			conn.Write(append(bh, '\n'))
			return
		}

		// process encrypted request body using existing helpers
		// Load server key and client public key (use ../keys/client_pub.asc or keys/client_pub.asc)
		serverEnt, err := loadEntity(resolveKeyPath("../keys/server_priv.asc"))
		if err != nil {
			// Try resolve with just keys dir
			serverEnt, err = loadEntity(resolveKeyPath("./keys/server_priv.asc"))
			if err != nil {
				resp := tcpRespHeader{Status: 500, ContentType: "text/plain", Length: 0}
				bh, _ := json.Marshal(resp)
				conn.Write(append(bh, '\n'))
				return
			}
		}

		// Try client public key local
		clientPubPath := resolveKeyPath("../keys/client_pub.asc")
		clientEnt, err := loadPublicEntity(clientPubPath)
		if err != nil {
			clientEnt, err = loadPublicEntity(resolveKeyPath("./keys/client_pub.asc"))
			if err != nil {
				resp := tcpRespHeader{Status: 502, ContentType: "text/plain", Length: 0}
				bh, _ := json.Marshal(resp)
				conn.Write(append(bh, '\n'))
				return
			}
		}

		md, err := openpgp.ReadMessage(bytes.NewReader(body), openpgp.EntityList{serverEnt, clientEnt}, nil, nil)
		if err != nil {
			resp := tcpRespHeader{Status: 400, ContentType: "text/plain", Length: len(err.Error())}
			bh, _ := json.Marshal(resp)
			conn.Write(append(bh, '\n'))
			conn.Write([]byte(err.Error()))
			return
		}
		plaintext, _ := io.ReadAll(md.UnverifiedBody)
		// For demo simply echo plaintext back encrypted to client
		response := plaintext

		var out bytes.Buffer
		_ = openpgp.ArmoredDetachSign(&out, serverEnt, bytes.NewReader(response), nil)
		sig := out.String()

		var enc bytes.Buffer
		wb, _ := openpgp.Encrypt(&enc, openpgp.EntityList{clientEnt}, serverEnt, nil, nil)
		wb.Write(response)
		wb.Close()

		resp := tcpRespHeader{Status: 200, ContentType: "application/httpe+pgp", Length: enc.Len()}
		bh, _ := json.Marshal(resp)
		conn.Write(append(bh, '\n'))
		conn.Write(enc.Bytes())
		// optionally send signature header line after body (not necessary in this simple framing)
		_ = sig
		return
	}

	// unsupported method
	resp := tcpRespHeader{Status: 405, ContentType: "text/plain", Length: 0}
	bh, _ := json.Marshal(resp)
	conn.Write(append(bh, '\n'))
}
