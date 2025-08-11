package database

import (
	"log"

	"github.com/IavilaGw/proyecto0/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	dsn := "host=localhost user=postgres password=password dbname=proyecto0 port=5432 sslmode=disable"
	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(" Error al conectar a la base de datos:", err)
	}

	DB.AutoMigrate(&models.Usuario{})
}
