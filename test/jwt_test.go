package main_test

import (
	"net/http"
	"testing"

	"github.com/gogf/gcache-adapter/adapter"
	"github.com/gogf/gf/database/gredis"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"

	"github.com/dobyte/jwt"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var (
	auth    jwt.JWT
	payload = jwt.Payload{
		"uid":     1,
		"account": "fuxiao",
	}
)

func init() {
	auth, _ = jwt.NewJwt(&jwt.Options{
		Issuer:      "backend",
		SignMethod:  jwt.HS256,
		SecretKey:   "secret",
		ExpiredTime: 3600,
		Locations:   "header:Authorization",
		IdentityKey: "uid",
	})

	gredis.SetConfig(&gredis.Config{
		Host: "127.0.0.1",
		Port: 6379,
		Db:   1,
	}, "jwt")
	auth.SetAdapter(adapter.NewRedis(g.Redis("jwt")))
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
	request, err := auth.Middleware(r.Request)
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

func Test_Server(t *testing.T) {
	s := g.Server()

	s.Group("", func(group *ghttp.RouterGroup) {
		// login
		group.POST("/login", func(r *ghttp.Request) {
			token, err := auth.Ctx(r.Context()).GenerateToken(payload)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "login success", token)
		})

		// logout
		group.DELETE("/logout", func(r *ghttp.Request) {
			if err := auth.Ctx(r.Context()).DestroyToken(r.Request); err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "logout success", nil)
		})

		// refresh token
		group.PUT("/refresh", func(r *ghttp.Request) {
			token, err := auth.Ctx(r.Context()).RefreshToken(r.Request)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "刷新成功", token)
		})

		group.Middleware(middleware)

		// get user profile information
		group.GET("/profile", func(r *ghttp.Request) {
			payload, err := auth.Ctx(r.Context()).GetPayload(r.Request)
			if err != nil {
				failed(r, http.StatusBadRequest, err.Error())
			}

			success(r, "success", payload)
		})
	})

	s.SetPort(8888)
	s.Run()
}

func Test_Middleware(t *testing.T) {
	token, err := auth.GenerateToken(payload)
	if err != nil {
		t.Fatal(err)
	}

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	r.Header.Add("Authorization", "Bearer "+token.Token)

	if r, err = auth.Ctx(r.Context()).Middleware(r); err != nil {
		t.Fatal(err)
	}

	if token, err = auth.Ctx(r.Context()).RefreshToken(r); err != nil {
		t.Fatal(err)
	}

	if payload, err = auth.Ctx(r.Context()).GetPayload(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(payload)
	}

	if token, err = auth.Ctx(r.Context()).GetToken(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(token)
	}

	if identity, err := auth.GetIdentity(r); err != nil {
		t.Fatal(err)
	} else {
		t.Log(identity)
	}
}
