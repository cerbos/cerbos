// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const authPairParts = 2

var (
	errAuthRequired = status.Error(codes.Unauthenticated, "authentication required")
	authSep         = []byte(":")
)

type JWTManager interface {
	GenerateToken(username string) (string, error)
	VerifyToken(tok string) (*Claims, error)
}

type Claims struct {
	jwt.StandardClaims
	User string `json:"username"`
	Role string `json:"role"`
}

func NewJWTManager(secret []byte, expireAfter time.Duration) *JWTHandler {
	return &JWTHandler{
		secret:      secret,
		expireAfter: expireAfter,
	}
}

type JWTHandler struct {
	secret      []byte
	expireAfter time.Duration
}

func (h *JWTHandler) GenerateToken(username string) (string, error) {
	claims := Claims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(h.expireAfter).Unix(),
		},
		User: username,
	}

	// shall we use different alg?
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(h.secret)
}

func (h *JWTHandler) VerifyToken(tok string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(
		tok,
		&Claims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}

			return h.secret, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func CheckCredentials(ctx context.Context, us UserStore, jm JWTManager, role Role) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errAuthRequired
	}

	header, ok := md["authorization"]
	if !ok || len(header) == 0 {
		return errAuthRequired
	}

	switch {
	case strings.HasPrefix(header[0], "Basic"):
		if us == nil {
			return status.Error(codes.NotFound, "basic authentication is not enabled")
		}
		// do basic auth
		encoded := strings.TrimSpace(strings.TrimPrefix(header[0], "Basic"))
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return status.Error(codes.Unauthenticated, "failed to decode credentials")
		}

		parts := bytes.Split(bytes.TrimSpace(decoded), authSep)
		if len(parts) != authPairParts {
			return status.Error(codes.Unauthenticated, "invalid credentials")
		}

		user, err := us.Get(string(parts[0]))
		if err != nil {
			return status.Error(codes.Unauthenticated, "incorrect credentials")
		}

		if err := bcrypt.CompareHashAndPassword(user.Password, parts[1]); err != nil {
			return status.Error(codes.Unauthenticated, "incorrect credentials")
		}

		if role != "" && user.Role != role {
			return status.Error(codes.Unauthenticated, "not authorized")
		}

		return nil
	case strings.HasPrefix(header[0], "Bearer"):
		if jm == nil {
			return status.Error(codes.Internal, "jwt is not enabled")
		}
		tokenString := strings.TrimSpace(strings.TrimPrefix(header[0], "Bearer"))

		claims, err := jm.VerifyToken(tokenString)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid token")
		}

		user, err := us.Get(claims.User)
		if err != nil {
			return status.Error(codes.Unauthenticated, "invalid user")
		}

		if time.Unix(claims.ExpiresAt, 0).Before(time.Now()) {
			return status.Error(codes.Unauthenticated, "token expired")
		}

		if role != "" && user.Role != role {
			return status.Error(codes.Unauthenticated, "not authorized")
		}

		return nil
	default:
		return status.Error(codes.Unauthenticated, "unsupported authentication method")
	}
}
