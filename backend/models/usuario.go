package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type Usuario struct {
	gorm.Model
	Nombre       string `gorm:"uniqueIndex;not null" json:"nombre"`
	Contrasena   string `gorm:"not null" json:"contrasena"`
	ImagenPerfil string `json:"imagen_perfil"`
}

// Se ejecuta antes de crear el usuario para asegurarse que la contraseña esté hasheada
func (u *Usuario) BeforeCreate(tx *gorm.DB) error {
	if u.Contrasena != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.Contrasena), 12)
		if err != nil {
			return err
		}
		u.Contrasena = string(hashedPassword)
	}
	return nil
}
