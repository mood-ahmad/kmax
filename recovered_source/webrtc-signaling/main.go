package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
)

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func main() {
	portFlag := flag.String("port", getEnv("PORT", "8443"), "Signaling server listen port")
	hostFlag := flag.String("host", getEnv("HOST", "0.0.0.0"), "Signaling server bind host")
	assetsFlag := flag.String("assets", getEnv("ASSETS", "./assets"), "Path to web frontend static assets")
	dataFlag := flag.String("data", getEnv("DATA_DIR", "./data"), "Directory for persistent user data")
	downloadsFlag := flag.String("downloads", getEnv("DOWNLOADS_DIR", "./downloads"), "Directory for downloaded recordings & files")
	certFlag := flag.String("cert", getEnv("TLS_CERT", "./certs/server.crt"), "TLS certificate file")
	keyFlag := flag.String("key", getEnv("TLS_KEY", "./certs/server.key"), "TLS private key file")
	tlsFlag := flag.Bool("tls", getEnv("USE_TLS", "true") != "false", "Enable HTTPS (TLS)")
	noAuthFlag := flag.Bool("no-auth", os.Getenv("NO_AUTH") == "true", "Disable login authentication")
	iceServersFlag := flag.String("ice_servers", getEnv("ICE_SERVERS", ""), "Comma-separated STUN/TURN ICE server URLs")
	stunServerFlag := flag.String("stun_server", "stun:stun.l.google.com:19302", "STUN server address (Deprecated, use -ice_servers)")
	debugFlag := flag.Bool("debug", os.Getenv("DEBUG") == "true", "Enable verbose debug logs")
	versionFlag := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if *versionFlag {
		fmt.Println("ScrcpyOverWebRTC Signaling Server v0.3.6 (Recovered)")
		return
	}

	log.Printf("====================================================")
	log.Printf("   ScrcpyOverWebRTC Signaling Server v0.3.6 (Recovered)")
	log.Printf("====================================================")

	// إدارة السر أوتوماتيك
	agentSecret := os.Getenv("AGENT_SECRET")
	if agentSecret == "" {
		secretFilePath := filepath.Join(*dataFlag, "agent.secret")
		if fileBytes, err := os.ReadFile(secretFilePath); err == nil {
			agentSecret = strings.TrimSpace(string(fileBytes))
		}
		
		if agentSecret == "" {
			b := make([]byte, 32)
			if _, err := rand.Read(b); err != nil {
				log.Fatalf("[Security] FATAL: Failed to generate cryptographically secure secret: %v", err)
			}
			agentSecret = hex.EncodeToString(b)
			
			if err := os.MkdirAll(*dataFlag, 0755); err != nil {
				log.Fatalf("[Security] FATAL: Failed to create data directory: %v", err)
			}
			
			if err := os.WriteFile(secretFilePath, []byte(agentSecret), 0600); err != nil {
				log.Fatalf("[Security] FATAL: Failed to write agent secret file: %v", err)
			}
			log.Printf("[Security] Generated new secure AGENT_SECRET and saved to %s", secretFilePath)
		}
		os.Setenv("AGENT_SECRET", agentSecret)
	}

	isDev := os.Getenv("DEV_MODE") == "true" || os.Getenv("DEBUG") == "true" || *debugFlag || *noAuthFlag || flag.Lookup("test.v") != nil
	insecureDefaults := map[string]bool{
		"cloudphone_production_agent_secret_2026": true,
		"changeme":                                 true,
		"secret":                                   true,
		"admin":                                    true,
		"123456":                                   true,
		"password":                                 true,
		"default":                                  true,
	}
	trimmedSecret := strings.ToLower(strings.TrimSpace(agentSecret))
	if !isDev {
		if trimmedSecret == "" {
			log.Fatalf("[Security] FATAL: Production mode requires a non-empty AGENT_SECRET! Please set AGENT_SECRET in your environment or enable DEV_MODE=true for local testing.")
		}
		if insecureDefaults[trimmedSecret] {
			log.Fatalf("[Security] FATAL: Production mode detected insecure placeholder AGENT_SECRET '%s'! Please set a unique, cryptographically secure secret.", agentSecret)
		}
	}

	store := NewPersistenceStore(*dataFlag)

	hub := NewHub(store)
	if *iceServersFlag != "" {
		urls := strings.Split(*iceServersFlag, ",")
		hub.iceServers = []IceServerConfig{{URLs: urls}}
	} else if *stunServerFlag != "" {
		hub.iceServers = []IceServerConfig{{URLs: []string{*stunServerFlag}}}
	}

	auth := NewAuthManager(*noAuthFlag, store)
	apiServer := NewAPIServer(hub, auth, store, *assetsFlag, *downloadsFlag)

	mux := http.NewServeMux()
	apiServer.RegisterRoutes(mux)

	addr := fmt.Sprintf("%s:%s", *hostFlag, *portFlag)
	useTLS := false
	var tlsConfig *tls.Config

	// 1. التحقق من الشهادات قبل التشغيل
	if *tlsFlag {
		if _, errCert := os.Stat(*certFlag); errCert == nil {
			if _, errKey := os.Stat(*keyFlag); errKey == nil {
				cert, err := tls.LoadX509KeyPair(*certFlag, *keyFlag)
				if err != nil {
					log.Fatalf("[Server] FATAL: Failed to load TLS certs: %v", err)
				}
				tlsConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}
				useTLS = true
			}
		}
	}

	// 2. محاولة فتح البورت (لو البورت مشغول، السيرفر هيقف هنا)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("[Server] FATAL: Failed to bind to port %s: %v", addr, err)
	}

	server := &http.Server{
		Addr:      addr,
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	// 3. طباعة "Listening on" بعد التأكد من أن البورت اتفتح والشهادات سليمة
	if useTLS {
		log.Printf("[Server] Starting HTTPS & WSS server on https://%s", addr)
		log.Printf("Listening on https://%s", addr) // هنا الكلمة حقيقية 100%
	} else {
		log.Printf("[Server] Starting HTTP & WS server on http://%s", addr)
		log.Printf("Listening on http://%s", addr) // هنا الكلمة حقيقية 100%
	}

	// 4. بدء السيرفر فعليًا
	go func() {
		if useTLS {
			if err := server.Serve(tls.NewListener(ln, tlsConfig)); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Server] TLS Serve error: %v", err)
			}
		} else {
			if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
				log.Fatalf("[Server] Serve error: %v", err)
			}
		}
	}()

	if *debugFlag {
		log.Println("[Server] Debug logging enabled")
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	log.Println("[Server] Shutting down signaling server...")
}
