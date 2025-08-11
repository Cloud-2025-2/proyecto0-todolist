package models

import "gorm.io/gorm"

type Usuario struct {
	gorm.Model
	Nombre       string `gorm:"uniqueIndex;not null" json:"nombre"`
	Contrasena   string `gorm:"not null" json:"contrasena"`
	ImagenPerfil string `json:"imagen_perfil"`
}
