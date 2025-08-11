package routes

import (
	"github.com/IavilaGw/proyecto0/controllers"
	"github.com/IavilaGw/proyecto0/middleware"
	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine) {
	api := r.Group("/api/v1")

	u := api.Group("/usuarios")
	u.POST("", controllers.CrearUsuario)
	u.POST("/iniciar-sesion", controllers.IniciarSesion)

	cat := api.Group("/categorias", middleware.Auth())
	cat.POST("", controllers.CrearCategoria)
	cat.DELETE("/:id", controllers.EliminarCategoria)
	cat.GET("", controllers.ListarCategorias)

	t := api.Group("/tareas", middleware.Auth())
	t.POST("", controllers.CrearTarea)
	t.PUT("/:id", controllers.ActualizarTarea)
	t.DELETE("/:id", controllers.EliminarTarea)
	t.GET("/usuario", controllers.ListarTareasPorUsuario)
}
