package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Echo!")
}

func main() {
	http.HandleFunc("/", handler)
	http.HandleFunc("/.well-known/acme-challenge/", handler)
	fmt.Println("Starting server on :8085")
	err := http.ListenAndServe(":8085", nil)
	if err != nil {
		fmt.Printf("error: %v\n", err)
		fmt.Println("shutting down server...")
		os.Exit(1)
	}
}
