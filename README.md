# JWT

A JWT plugin for gin, iris, go-frame, beego, go-zero, go-chassis, go-kit and other frameworks

## Use

Download and install

```shell
go get github.com/dobyte/jwt
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
	auth, err := jwt.NewJWT(
		jwt.WithIssuer("backend"),
		jwt.WithSignAlgorithm(jwt.HS256),
		jwt.WithSecretKey("secret"),
		jwt.WithValidDuration(3600),
		jwt.WithLookupLocations("header:Authorization"),
		jwt.WithIdentityKey("uid"),
	)
	if err != nil {
		log.Fatal("create jwt instance failed:" + err.Error())
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

View demo [example/server.go](example/server.go)

## API Demo

View demo [example/jwt.postman.json](example/jwt.postman.json)