package jwt_test

import (
	"github.com/dobyte/jwt"
	"net/http"
	"testing"
	"time"
)

var (
	auth    *jwt.JWT
	payload jwt.Payload
)

func init() {
	auth, _ = jwt.NewJWT(
		jwt.WithIssuer("backend"),
		jwt.WithSignAlgorithm(jwt.HS256),
		jwt.WithSecretKey("secret"),
		jwt.WithValidDuration(3600),
		jwt.WithLookupLocations("header:Authorization"),
		jwt.WithIdentityKey("uid"),
	)

	payload = jwt.Payload{
		"uid":     1,
		"account": "fuxiao",
	}
}

func TestJWT_GenerateToken(t *testing.T) {
	token, err := auth.GenerateToken(payload)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", token)

	time.Sleep(time.Second)

	token, err = auth.RefreshToken(token.Token)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", token)

	p, err := auth.ExtractPayload(token.Token)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", p)

	identity, err := auth.ExtractIdentity(token.Token)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", identity)
}

func TestJWT_Middleware(t *testing.T) {
	token, err := auth.GenerateToken(payload)
	if err != nil {
		t.Fatal(err)
	}

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	r.Header.Add("Authorization", "Bearer "+token.Token)

	if r, err = auth.Http().Middleware(r); err != nil {
		t.Fatal(err)
	}

	if token, err = auth.Http().RefreshToken(r); err != nil {
		t.Fatal(err)
	}

	if payload, err = auth.Http().ExtractPayload(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(payload)
	}

	if token, err = auth.Http().ExtractToken(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(token)
	}

	if identity, err := auth.Http().ExtractIdentity(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(identity)
	}
}
