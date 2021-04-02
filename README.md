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
	"time"
	"github.com/gogf/gf/frame/g"
	"github.com/dobyte/gf-jwt"
)

func main() {
	auth, err := jwt.NewJwt(&jwt.Jwt{
		Realm:         "backend",
		Algorithm:     "HS256",
		Secret:        "secret",
		ExpireTime:    3600 * time.Second,
		RefreshTime:   7200 * time.Second,
		IsUnique:      true,
		IdentityKey:   "id",
		TokenLookup:   "header:Authorization",
		TokenHeadName: "Bearer",
	})

	if err != nil {
		log.Fatalf("Jwt init failure:%s \n", err.Error())
	}

	token, err := auth.GenerateToken(g.Map{
		"id":      1,
		"account": "fuxiao",
	})

	fmt.Println(token)
}
```

## Example

View demo [example/main.go](example/main.go)

## API Demo

View demo [example/jwt.postman.json](example/jwt.postman.json)