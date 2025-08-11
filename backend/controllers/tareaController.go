package controllers

import (
	"net/http"
	"time"

	database "proyecto0-todolist/config"

	"proyecto0-todolist/middleware"

	"proyecto0-todolist/models"

	"github.com/gin-gonic/gin"
)

type CrearTareaDTO struct {
	Texto             string `json:"texto" binding:"required"`
	FechaTentativaFin string `json:"fechaTentativaFin"`
	IDCategoria       uint   `json:"id_categoria" binding:"required"`
}

type ActualizarTareaDTO struct {
	Texto             *string `json:"texto"`
	FechaTentativaFin *string `json:"fechaTentativaFin"`
	Estado            *string `json:"estado"`
}

// POST /tareas  → Tarea creada
func CrearTarea(c *gin.Context) {
	var in CrearTareaDTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var fecha *time.Time
	if in.FechaTentativaFin != "" {
		p, err := time.Parse("2006-01-02", in.FechaTentativaFin)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "fechaTentativaFin debe ser yyyy-mm-dd"})
			return
		}
		fecha = &p
	}

	t := models.Tarea{
		Texto:             in.Texto,
		FechaTentativaFin: fecha,
		Estado:            "Sin Empezar",
		IDCategoria:       in.IDCategoria,
		IDUsuario:         middleware.UserID(c), // viene del token
	}

	if err := database.DB.Create(&t).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo crear la tarea"})
		return
	}
	c.JSON(http.StatusCreated, t)
}

// PUT /tareas/:id  → Tarea actualizada
func ActualizarTarea(c *gin.Context) {
	var t models.Tarea
	if err := database.DB.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tarea no encontrada"})
		return
	}

	if t.IDUsuario != middleware.UserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no tienes permisos para actualizar esta tarea"})
		return
	}

	var in ActualizarTareaDTO
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if in.Texto != nil {
		t.Texto = *in.Texto
	}
	if in.Estado != nil {
		t.Estado = *in.Estado
	}
	if in.FechaTentativaFin != nil && *in.FechaTentativaFin != "" {
		p, err := time.Parse("2006-01-02", *in.FechaTentativaFin)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "fechaTentativaFin debe ser yyyy-mm-dd"})
			return
		}
		t.FechaTentativaFin = &p
	}

	if err := database.DB.Save(&t).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo actualizar"})
		return
	}
	c.JSON(http.StatusOK, t)
}

// DELETE /tareas/:id  → Confirmación de eliminación
func EliminarTarea(c *gin.Context) {
	var t models.Tarea
	if err := database.DB.First(&t, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tarea no encontrada"})
		return
	}

	if t.IDUsuario != middleware.UserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no tienes permisos para eliminar esta tarea"})
		return
	}

	if err := database.DB.Delete(&t).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no se pudo eliminar"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// GET /tareas/usuario  → Lista de tareas del usuario autenticado
func ListarTareasPorUsuario(c *gin.Context) {
	var tareas []models.Tarea
	if err := database.DB.Where("id_usuario = ?", middleware.UserID(c)).Find(&tareas).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "no se pudo listar"})
		return
	}
	c.JSON(http.StatusOK, tareas)
}

// GET /tareas/:id  → Detalles de la tarea
func ObtenerTareaPorID(c *gin.Context) {
	var tarea models.Tarea

	// Obtener la tarea por ID
	if err := database.DB.First(&tarea, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "tarea no encontrada"})
		return
	}

	// Verificar que la tarea pertenezca al usuario autenticado
	if tarea.IDUsuario != middleware.UserID(c) {
		c.JSON(http.StatusForbidden, gin.H{"error": "no tienes permisos para ver esta tarea"})
		return
	}

	// Cargar los datos relacionados (usuario y categoría)
	if err := database.DB.Preload("Usuario").Preload("Categoria").First(&tarea, tarea.ID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error al cargar datos relacionados"})
		return
	}

	c.JSON(http.StatusOK, tarea)
}
