// Package main implements the AzzurroTech Platform (atp) as the central integration hub
package main

import (
	"flag"
	"fmt"
	"log"

	"azzurrotech/atp/web"
)

func main() {
	port := flag.String("port", "8080", "Port to listen on (default: 8080)")
	help := flag.Bool("help", false, "Show help message")
	version := flag.Bool("version", false, "Show version information")

	flag.Parse()

	if *help {
		fmt.Println("Usage: atp [options]")
		fmt.Println("  --port     Set the port to listen on (default: 8080)")
		fmt.Println("  --help     Show this help message")
		fmt.Println("  --version  Show version information")
		return
	}

	if *version {
		fmt.Println("AzzurroTech Platform (ATP) v1.0.0")
		fmt.Println("Central Integration Hub for AzzurroTech Services")
		fmt.Println("Copyright 2025 Azzurro Technology Inc.")
		fmt.Println("Services: stenella, pod, song, shepherd, and emperor42 platforms")
		return
	}

	// Create and start the ATP platform service
	atpService := web.NewATPService(*port)
	if err := atpService.Start(); err != nil {
		log.Fatalf("Failed to start ATP platform: %v", err)
	}
}
