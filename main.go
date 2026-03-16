package main

import (
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Wazuh API Server is Running")
	})
	
	// สำหรับรัน Local ทดสอบ
	fmt.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
