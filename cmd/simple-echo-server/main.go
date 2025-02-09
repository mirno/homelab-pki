package main

import (
	"embed"
	"fmt"
	"net/http"
	"os"
	"time"
)

//go:embed webroot/*
var embedWebRoot embed.FS

const (
	timeoutDefault = 10
	port           = "8085"
	acmeWebroot    = "./webroot" // Directory to store ACME challenge files

)

func echoHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Echo!")
}

func main() {

	mux := http.NewServeMux()
	// muecho handler
	mux.HandleFunc("/", echoHandler)

	// Serve ACME challenges from a directory
	acmeHandler := http.StripPrefix("/.well-known/acme-challenge/", http.FileServer(http.FS(embedWebRoot))) // http.Dir(acmeWebroot)
	mux.Handle("/.well-known/acme-challenge/", acmeHandler)

	server := &http.Server{
		Addr:         "0.0.0.0:" + port,
		Handler:      mux,
		ReadTimeout:  timeoutDefault * time.Second, // Maximum duration for reading the request
		WriteTimeout: timeoutDefault * time.Second, // Maximum duration for writing the response
		IdleTimeout:  timeoutDefault * time.Second, // Maximum duration for idle connections
	}

	fmt.Println("Starting server on :" + port)
	err := server.ListenAndServe()
	if err != nil {
		fmt.Printf("error: %v\n", err)
		fmt.Println("shutting down server...")
		os.Exit(1)
	}
}
