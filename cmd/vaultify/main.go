package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/vaultify/vaultify/internal/scanner"
	"github.com/vaultify/vaultify/internal/server"
	"github.com/vaultify/vaultify/internal/session"
)

const version = "0.1.0"

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
	srv := server.NewServer(sc, sm)

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
