package models

import "gorm.io/gorm"

type Categoria struct {
	gorm.Model
	Nombre      string `gorm:"uniqueIndex;not null" json:"nombre"`
	Descripcion string `json:"descripcion"`
}
