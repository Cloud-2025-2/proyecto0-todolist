package auth

import (
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Obtener secret desde variables de entorno
func getSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		panic("JWT_SECRET no está configurado")
	}
	return []byte(secret)
}

type Claims struct {
	UserID   uint   `json:"user_id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GenerateToken(id uint, username string, ttl time.Duration) (string, error) {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}

	claims := &Claims{
		UserID:   id,
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "proyecto0-todolist",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(getSecret())
}

func ParseToken(tokenStr string) (*Claims, error) {
	tok, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(_ *jwt.Token) (any, error) {
		return getSecret(), nil
	})
	if err != nil || !tok.Valid {
		return nil, err
	}
	return tok.Claims.(*Claims), nil
}
