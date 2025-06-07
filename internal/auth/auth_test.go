package auth_test

import (
	"testing"
	"time"
	"net/http"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"chirpy/internal/auth"

)

func TestMakeAndValidateJWT(t *testing.T) {
	secret := "supersecretkey"
	userID := uuid.New()

	token, err := auth.MakeJWT(userID, secret, time.Minute)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	parsedID, err := auth.ValidateJWT(token, secret)
	require.NoError(t, err)
	require.Equal(t, userID, parsedID)
}

func TestValidateJWT_ExpiredToken(t *testing.T) {
	secret := "supersecretkey"
	userID := uuid.New()

	token, err := auth.MakeJWT(userID, secret, -1*time.Minute)
	require.NoError(t, err)

	_, err = auth.ValidateJWT(token, secret)
	require.Error(t, err)
}

func TestValidateJWT_WrongSecret(t *testing.T) {
	userID := uuid.New()
	correctSecret := "correctsecret"
	wrongSecret := "wrongsecret"

	token, err := auth.MakeJWT(userID, correctSecret, time.Minute)
	require.NoError(t, err)

	_, err = auth.ValidateJWT(token, wrongSecret)
	require.Error(t, err)
}

func TestGetBearerToken(t *testing.T) {
	t.Run("valid header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer abc.def.ghi")

		token, err := auth.GetBearerToken(headers)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if token != "abc.def.ghi" {
			t.Errorf("expected token to be 'abc.def.ghi', got %v", token)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		headers := http.Header{}

		_, err := auth.GetBearerToken(headers)
		if err == nil {
			t.Fatal("expected error, got none")
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Token abc.def.ghi")

		_, err := auth.GetBearerToken(headers)
		if err == nil {
			t.Fatal("expected error, got none")
		}
	})
}

func TestMakeRefreshToken(t *testing.T) {
	token, err := auth.MakeRefreshToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(token) != 64 { // 32 bytes -> 64 hex chars
		t.Fatalf("unexpected token length: got %d, want 64", len(token))
	}
	t.Logf("Generated token: %s", token)
}

