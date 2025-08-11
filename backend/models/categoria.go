package models

import "gorm.io/gorm"

type Categoria struct {
	gorm.Model
	Nombre      string `gorm:"uniqueIndex;not null" json:"nombre"`
	Descripcion string `json:"descripcion"`
	// Adicional: relacion con el usuario
	IDUsuario uint `gorm:"not null" json:"id_usuario"`

	Usuario Usuario `gorm:"foreignKey:IDUsuario"`
}
