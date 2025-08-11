package database

import (
	"fmt"
	"log"
	"os"

	"proyecto0-todolist/models"

	"github.com/joho/godotenv"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func Connect() {
	// Cargar variables de entorno
	loadEnv()

	// Construir DSN desde variables de entorno
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SSL_MODE"),
	)

	var err error
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Error al conectar a la base de datos:", err)
	}

	log.Printf("Conectado a la base de datos: %s en %s:%s",
		os.Getenv("DB_NAME"),
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"))

	// Auto-migrar modelos
	DB.AutoMigrate(&models.Usuario{}, &models.Categoria{}, &models.Tarea{})
	log.Println("Modelos migrados exitosamente")
}

func loadEnv() {
	// Intentar cargar desde .env
	if err := godotenv.Load(); err != nil {
		log.Println("⚠️  Archivo .env no encontrado, usando variables de entorno del sistema")
	}

	// Validar variables requeridas
	requiredEnvVars := []string{
		"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSL_MODE",
		"SERVER_PORT", "JWT_SECRET",
	}

	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			log.Fatalf("Variable de entorno requerida no encontrada: %s", envVar)
		}
	}
}

// GetDB retorna la instancia de la base de datos
func GetDB() *gorm.DB {
	return DB
}
