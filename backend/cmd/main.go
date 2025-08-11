package main

import (
	database "github.com/IavilaGw/proyecto0/config"
	"github.com/IavilaGw/proyecto0/models"
	"github.com/IavilaGw/proyecto0/routes"
	"github.com/gin-gonic/gin"
)

func main() {
	database.Connect()
	database.DB.AutoMigrate(&models.Usuario{}, &models.Categoria{}, &models.Tarea{})

	r := gin.Default()

	//r.GET("/health", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

	routes.Register(r)

	r.Run(":8080")
}
