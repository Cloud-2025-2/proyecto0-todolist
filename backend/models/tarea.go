package models

import (
	"time"

	"gorm.io/gorm"
)

type Tarea struct {
	gorm.Model
	Texto             string     `json:"texto"`
	FechaCreacion     time.Time  `json:"fechaCreacion" gorm:"autoCreateTime"`
	FechaTentativaFin *time.Time `json:"fechaTentativaFin"`
	Estado            string     `json:"estado" gorm:"default:'Sin Empezar'"`
	IDCategoria       uint       `json:"id_categoria"`
	IDUsuario         uint       `json:"id_usuario"`
}
