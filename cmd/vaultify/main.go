package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/vaultify/vaultify/internal/auditlog"
	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/server"
	"github.com/vaultify/vaultify/internal/session"
)

// Set at link time for release builds: -ldflags "-X main.version=0.1.7"
var version = "0.1.7"

func main() {
	port := flag.Int("port", 9471, "HTTP server port")
	noBrowser := flag.Bool("no-browser", false, "Do not open the browser automatically")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("Vaultify v%s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	url := fmt.Sprintf("http://localhost:%d", *port)

	// Check if already running
	resp, err := http.Get(url + "/api/ping")
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			fmt.Println("  Vaultify is already running. Opening browser...")
			openBrowser(url)
			return
		}
	}

	fmt.Println()
	fmt.Println("  Vaultify — credential remediation toolkit")
	fmt.Printf("  Starting on %s\n", url)
	fmt.Println()

	sc := scanner.NewScanner()
	sm := session.NewManager("")

	logDir := filepath.Join(os.TempDir(), "vaultify-scans", ".logs")
	os.MkdirAll(logDir, 0o700)
	appLogPath := filepath.Join(logDir, "vaultify-app.log")
	appLogFile, err := os.OpenFile(appLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		multiWriter := io.MultiWriter(os.Stderr, appLogFile)
		log.SetOutput(multiWriter)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
	}
	log.Printf("vaultify v%s starting (os=%s arch=%s pid=%d)", version, runtime.GOOS, runtime.GOARCH, os.Getpid())

	logger, err := auditlog.New(logDir)
	if err != nil {
		log.Fatalf("Failed to initialise logger: %v", err)
	}
	logger.Info("startup", fmt.Sprintf("vaultify v%s starting on port %d", version, *port))

	srv := server.NewServer(sc, sm, logger)

	go func() {
		if err := srv.Start(*port); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	if !*noBrowser {
		time.Sleep(300 * time.Millisecond)
		openBrowser(url)
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Printf("vaultify shutting down")
	if appLogFile != nil {
		appLogFile.Close()
	}
	fmt.Println("\n  Shutting down...")
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
