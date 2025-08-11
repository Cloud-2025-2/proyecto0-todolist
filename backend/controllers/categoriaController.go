package controllers

import (
	"net/http"

	database "proyecto0-todolist/config"

	"proyecto0-todolist/middleware"

	"proyecto0-todolist/models"

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
		IDUsuario:   middleware.UserID(c),
	}

	if err := database.DB.Create(&cat).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo crear la categoría"})
		return
	}

	c.JSON(http.StatusCreated, cat)
}

func EliminarCategoria(c *gin.Context) {
	var cat models.Categoria
	if err := database.DB.First(&cat, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "categoría no encontrada"})
		return
	}

	if cat.IDUsuario != middleware.UserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no tienes permisos para eliminar esta categoría"})
		return
	}

	if err := database.DB.Delete(&cat).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo eliminar"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

func ListarCategorias(c *gin.Context) {
	var categorias []models.Categoria
	if err := database.DB.Where("id_usuario = ?", middleware.UserID(c)).Find(&categorias).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo listar"})
		return
	}
	c.JSON(http.StatusOK, categorias)
}

// Adicional
func ObtenerCategoriaPorID(c *gin.Context) {
	var cat models.Categoria
	if err := database.DB.First(&cat, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "categoría no encontrada"})
		return
	}

	// Verificar que la categoría pertenezca al usuario autenticado
	if cat.IDUsuario != middleware.UserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no tienes permisos para ver esta categoría"})
		return
	}

	c.JSON(http.StatusOK, cat)
}
