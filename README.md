# gf-jwt

GoFrame HTTP JWT Plugin

## Use

Download and install

```shell
go get github.com/dobyte/gf-jwt
```

Demo

```go
package main

import (
    "fmt"
    "log"
    "github.com/dobyte/gf-jwt"
)

func main() {
    auth := jwt.NewJwt(&jwt.Options{
        Realm:       "backend",
        Algorithm:   "HS256",
        Secret:      "secret",
        ExpireTime:  3600,
        RefreshTime: 7200,
        TokenLookup: "header:Authorization",
    })
    
    token, err := auth.GenerateToken(g.Map{
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