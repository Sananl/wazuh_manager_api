package handler

import (
	"net/http"

	"api/logic"

	"github.com/gin-gonic/gin"
)

var router *gin.Engine

func Handler(w http.ResponseWriter, r *http.Request) {
	if router == nil {
		router = logic.InitRouter()
	}
	router.ServeHTTP(w, r)
}
