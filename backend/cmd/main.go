package main

import (
	"fmt"
	"log"
	"os"

	database "proyecto0-todolist/config"

	"proyecto0-todolist/routes"

	"github.com/gin-gonic/gin"
)

func main() {
	// Configurar Gin según el entorno
	if os.Getenv("ENV") == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Conectar a la base de datos
	database.Connect()

	// Crear router
	r := gin.Default()

	// Middleware de logging
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Ruta de health check
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"status": "ok",
			"env":    os.Getenv("ENV"),
			"db":     "connected",
		})
	})

	// Registrar rutas de la API
	routes.Register(r)

	// Obtener puerto desde variables de entorno
	port := os.Getenv("SERVER_PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Servidor iniciando en puerto %s", port)
	log.Printf("Entorno: %s", os.Getenv("ENV"))

	if err := r.Run(fmt.Sprintf(":%s", port)); err != nil {
		log.Fatal("Error al iniciar el servidor:", err)
	}
}
