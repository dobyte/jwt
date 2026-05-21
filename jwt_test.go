package jwt_test

import (
	"testing"
	"time"

	"github.com/dobyte/jwt"
)

var (
	auth    *jwt.JWT
	payload jwt.Payload
)

func init() {
	auth, _ = jwt.NewJWT(
		jwt.WithAudience("https://api.example.com"),
		jwt.WithIssuer("backend"),
		jwt.WithSignAlgorithm(jwt.HS256),
		jwt.WithSecretKey("secret"),
		jwt.WithValidDuration(3600),
		jwt.WithLookupLocations("header:Authorization"),
	)

	payload = jwt.Payload{
		"account": "fuxiao",
	}
}

func TestJWT_GenerateToken(t *testing.T) {
	token, err := auth.GenerateToken("1")
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

	p, err := auth.ParseToken(token.Token)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("%+v", p)
	t.Logf("%+v", p.Subject())
}

// func TestJWT_Middleware(t *testing.T) {
// 	token, err := auth.GenerateToken(payload)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	r, err := http.NewRequest(http.MethodGet, "/", nil)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	r.Header.Add("Authorization", "Bearer "+token.Token)

// 	if r, err = auth.Http().Middleware(r); err != nil {
// 		t.Fatal(err)
// 	}

// 	if token, err = auth.Http().RefreshToken(r); err != nil {
// 		t.Fatal(err)
// 	}

// 	if payload, err = auth.Http().ExtractPayload(r); err != nil {
// 		t.Fatal(err)
// 	} else {
// 		t.Log(payload)
// 	}

// 	if token, err = auth.Http().ExtractToken(r); err != nil {
// 		t.Fatal(err)
// 	} else {
// 		t.Log(token)
// 	}

// 	if identity, err := auth.Http().ExtractIdentity(r); err != nil {
// 		t.Fatal(err)
// 	} else {
// 		t.Log(identity)
// 	}
// }
