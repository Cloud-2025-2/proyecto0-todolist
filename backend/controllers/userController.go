package controllers

import (
	"net/http"
	"time"

	"github.com/IavilaGw/proyecto0/auth"
	database "github.com/IavilaGw/proyecto0/config"
	"github.com/IavilaGw/proyecto0/models"
	"github.com/gin-gonic/gin"
)

type CrearUsuarioDTO struct {
	Nombre       string `json:"nombre" binding:"required"`
	Contrasena   string `json:"contrasena" binding:"required"`
	ImagenPerfil string `json:"imagen_perfil"`
}

func CrearUsuario(c *gin.Context) {
	var in CrearUsuarioDTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	u := models.Usuario{Nombre: in.Nombre, Contrasena: in.Contrasena, ImagenPerfil: in.ImagenPerfil}
	if err := database.DB.Create(&u).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo crear el usuario"})
		return
	}
	c.JSON(http.StatusCreated, u)
}

type IniciarSesionDTO struct {
	Nombre     string `json:"nombre" binding:"required"`
	Contrasena string `json:"contrasena" binding:"required"`
}

func IniciarSesion(c *gin.Context) {
	var in IniciarSesionDTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var u models.Usuario
	if err := database.DB.Where("nombre = ?", in.Nombre).First(&u).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
		return
	}
	if u.Contrasena != in.Contrasena {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "credenciales inválidas"})
		return
	}
	tok, err := auth.GenerateToken(u.ID, u.Nombre, 24*time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo generar token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tok})
}
