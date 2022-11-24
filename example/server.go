package main

import (
	"github.com/gogf/gcache-adapter/adapter"
	"github.com/gogf/gf/database/gredis"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"net/http"

	"github.com/dobyte/jwt"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var (
	auth    *jwt.JWT
	payload = jwt.Payload{
		"uid":     1,
		"account": "fuxiao",
	}
)

func init() {
	gredis.SetConfig(&gredis.Config{
		Host: "127.0.0.1",
		Port: 6379,
		Db:   1,
	}, "jwt")

	auth = jwt.NewJWT(
		jwt.WithIssuer("backend"),
		jwt.WithSignAlgorithm(jwt.HS256),
		jwt.WithSecretKey("secret"),
		jwt.WithValidDuration(3600),
		jwt.WithLookupLocations("header:Authorization"),
		jwt.WithIdentityKey("uid"),
		jwt.WithStore(adapter.NewRedis(g.Redis("jwt"))),
	)
}

func failed(r *ghttp.Request, status int, message string) {
	_ = r.Response.WriteJsonExit(Response{
		Status:  status,
		Message: message,
	})
}

func success(r *ghttp.Request, message string, data interface{}) {
	_ = r.Response.WriteJsonExit(Response{
		Status:  http.StatusOK,
		Message: message,
		Data:    data,
	})
}

func middleware(r *ghttp.Request) {
	request, err := auth.Http().Middleware(r.Request)
	if err != nil {
		switch {
		case jwt.IsInvalidToken(err):
			failed(r, http.StatusUnauthorized, "token is invalid")
		case jwt.IsExpiredToken(err):
			failed(r, http.StatusUnauthorized, "token is expired")
		case jwt.IsMissingToken(err):
			failed(r, http.StatusUnauthorized, "token is missing")
		case jwt.IsAuthElsewhere(err):
			failed(r, http.StatusUnauthorized, "auth elsewhere")
		default:
			failed(r, http.StatusUnauthorized, "unauthorized")
		}
	}

	r.Request = request

	r.Middleware.Next()
}

func main() {
	s := g.Server()

	s.Group("", func(group *ghttp.RouterGroup) {
		// login
		group.POST("/login", func(r *ghttp.Request) {
			token, err := auth.GenerateToken(payload)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "login success", token)
		})

		// logout
		group.DELETE("/logout", func(r *ghttp.Request) {
			if err := auth.Http().DestroyToken(r.Request); err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "logout success", nil)
		})

		// refresh token
		group.PUT("/refresh", func(r *ghttp.Request) {
			token, err := auth.Http().RefreshToken(r.Request)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "refresh success", token)
		})

		group.Middleware(middleware)

		// get user profile information
		group.GET("/profile", func(r *ghttp.Request) {
			info, err := auth.Http().ExtractPayload(r.Request)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "get profile success", info)
		})
	})

	s.SetPort(8888)
	s.Run()
}
