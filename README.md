# JWT

A JWT plugin for gin, iris, go-frame, beego, go-zero, go-chassis, go-kit and other frameworks

## Use

Download and install

```shell
go get github.com/dobyte/jwt
```

API

```go
// Ctx Which shallowly clones current object and sets the context for next operation.
Ctx(ctx context.Context) JWT

// SetAdapter Set a cache adapter for authentication.
SetAdapter(adapter Adapter) JWT

// Middleware Implemented basic JWT permission authentication.
Middleware(r *http.Request) (*http.Request, error)

// GenerateToken Generates and returns a new token object with payload.
GenerateToken(payload Payload) (*Token, error)

// RetreadToken Retreads and returns a new token object depend on old token.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
RetreadToken(token string, ignoreExpired ...bool) (*Token, error)

// RefreshToken Generates and returns a new token object from.
RefreshToken(r *http.Request) (*Token, error)

// DestroyToken Destroy the cache of a token.
DestroyToken(r *http.Request) error

// DestroyIdentity Destroy the identification mark.
DestroyIdentity(identity interface{}) error

// GetToken Get token from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
GetToken(r *http.Request, ignoreExpired ...bool) (*Token, error)

// GetPayload Retrieve payload from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
GetPayload(r *http.Request, ignoreExpired ...bool) (payload Payload, err error)

// GetIdentity Retrieve identity from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
GetIdentity(r *http.Request, ignoreExpired ...bool) (interface{}, error)
```

Demo

```go
package main

import (
	"fmt"
	"log"
	"github.com/dobyte/jwt"
)

func main() {
	auth, err := jwt.NewJwt(&jwt.Options{
		Issuer:      "backend",
		SignMethod:  "HS256",
		SecretKey:   "secret",
		ExpiredTime: 3600,
		RefreshTime: 7200,
		Locations:   "header:Authorization",
	})
	if err != nil {
		log.Fatal("init jwt failed:" + err.Error())
	}

	token, err := auth.GenerateToken(jwt.Payload{
		"uid":     1,
		"account": "fuxiao",
	})
	if err != nil {
		log.Fatal("Generate token failed:" + err.Error())
	}

	fmt.Println(token)
}
```

## Example

View demo [test/jwt_test.go](test/jwt_test.go)

## API Demo

View demo [test/jwt.postman.json](test/jwt.postman.json)