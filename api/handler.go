package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

var router *gin.Engine

func Handler(w http.ResponseWriter, r *http.Request) {
	if router == nil {
		router = InitRouter()
	}
	router.ServeHTTP(w, r)
}
