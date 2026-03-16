package main

import (
	"api/logic"
	"fmt"
	"net/http"
	"os"
)

func main() {
	r := logic.InitRouter()
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Println("Server starting on :" + port)
	r.Run(":" + port)
}

// สำหรับ Vercel (ถ้าต้องการใช้ Serverless Function)
func Handler(w http.ResponseWriter, r *http.Request) {
	router := logic.InitRouter()
	router.ServeHTTP(w, r)
}
