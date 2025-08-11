package routes

import (
	"proyecto0-todolist/controllers"
	"proyecto0-todolist/middleware"

	"github.com/gin-gonic/gin"
)

func Register(r *gin.Engine) {
	api := r.Group("/api/v1")

	u := api.Group("/usuarios")
	u.POST("", controllers.CrearUsuario)
	u.POST("/iniciar-sesion", controllers.IniciarSesion)

	cat := api.Group("/categorias", middleware.Auth())
	cat.POST("", controllers.CrearCategoria)
	cat.GET("", controllers.ListarCategorias)
	cat.GET("/:id", controllers.ObtenerCategoriaPorID)
	cat.DELETE("/:id", controllers.EliminarCategoria)

	t := api.Group("/tareas", middleware.Auth())
	t.POST("", controllers.CrearTarea)
	t.GET("/:id", controllers.ObtenerTareaPorID)
	t.PUT("/:id", controllers.ActualizarTarea)
	t.DELETE("/:id", controllers.EliminarTarea)
	t.GET("/usuario", controllers.ListarTareasPorUsuario)
}
