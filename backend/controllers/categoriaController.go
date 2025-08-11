package controllers

import (
	"net/http"

	database "github.com/IavilaGw/proyecto0/config"
	"github.com/IavilaGw/proyecto0/models"
	"github.com/gin-gonic/gin"
)

type CrearCategoriaDTO struct {
	Nombre      string `json:"nombre" binding:"required"`
	Descripcion string `json:"descripcion" binding:"required"`
}

func CrearCategoria(c *gin.Context) {
	var in CrearCategoriaDTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cat := models.Categoria{
		Nombre:      in.Nombre,
		Descripcion: in.Descripcion,
	}

	if err := database.DB.Create(&cat).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo crear la categoría"})
		return
	}

	c.JSON(http.StatusCreated, cat)
}

func EliminarCategoria(c *gin.Context) {
	id := c.Param("id")
	if err := database.DB.Delete(&models.Categoria{}, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo eliminar"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func ListarCategorias(c *gin.Context) {
	var categorias []models.Categoria
	if err := database.DB.Find(&categorias).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo listar"})
		return
	}
	c.JSON(http.StatusOK, categorias)
}
