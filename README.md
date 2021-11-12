# JWT

A JWT plugin for gin, iris, go-frame, beego, go-zero, go-chassis, go-kit and other frameworks

## Use

Download and install

```shell
go get github.com/dobyte/jwt
```

API

```go
// Middleware Implemented basic JWT permission authentication.
Middleware(r *http.Request) (*http.Request, error)

// GenerateToken Generates and returns a new token object with payload.
GenerateToken(payload Payload) (*Token, error)

// RefreshToken Generates and returns a new token object from.
RefreshToken(r *http.Request) (*Token, error)

// RetreadToken Retreads and returns a new token object depend on old token.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
RetreadToken(token string, ignoreExpired ...bool) (*Token, error)

// GetToken Get token from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
GetToken(r *http.Request, ignoreExpired ...bool) (*Token, error)
        
// GetPayload Retrieve payload from request.
// By default, the token expired error doesn't ignored.
// You can ignore expired error by setting the `ignoreExpired` parameter.
GetPayload(r *http.Request, ignoreExpired ...bool) (payload Payload, err error)
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
    auth := jwt.NewJwt(&jwt.Options{
        Issuer:      "backend",
        SignMethod:  "HS256",
        SecretKey:   "secret",
        ExpiredTime: 3600,
        RefreshTime: 7200,
        Locations:   "header:Authorization",
    })
    
    token, err := auth.GenerateToken(jwt.Payload{
        "id":      1,
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