package main_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"

	"github.com/dobyte/jwt"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var auth, _ = jwt.NewJwt(&jwt.Options{
	Issuer:      "backend",
	SignMethod:  jwt.HS256,
	SecretKey:   "secret",
	ExpiredTime: 3600,
	Locations:   "header:Authorization",
})

func responseFail(r *ghttp.Request, status int, message string) {
	_ = r.Response.WriteJsonExit(Response{
		Status:  status,
		Message: message,
	})
}

func responseSuccess(r *ghttp.Request, message string, data interface{}) {
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
			responseFail(r, http.StatusUnauthorized, "token is invalid")
		case jwt.IsExpiredToken(err):
			responseFail(r, http.StatusUnauthorized, "token is expired")
		case jwt.IsMissingToken(err):
			responseFail(r, http.StatusUnauthorized, "token is missing")
		default:
			responseFail(r, http.StatusUnauthorized, "unauthorized")
		}
	}

	r.Request = request

	r.Middleware.Next()
}

func Test_Server(t *testing.T) {
	s := g.Server()

	s.Group("", func(group *ghttp.RouterGroup) {
		group.POST("/login", func(r *ghttp.Request) {
			token, err := auth.GenerateToken(jwt.Payload{
				"id":      1,
				"account": "fuxiao",
			})

			if err != nil {
				responseFail(r, http.StatusBadRequest, "授权失败")
				return
			}

			responseSuccess(r, "login success", token)
		})

		group.DELETE("/logout", func(r *ghttp.Request) {
			responseSuccess(r, "logout success", nil)
		})

		group.PUT("/refresh", func(r *ghttp.Request) {
			token, err := auth.RefreshToken(r.Request)
			if err != nil {
				responseFail(r, http.StatusBadRequest, "refresh token failed")
			}

			responseSuccess(r, "刷新成功", token)
		})
	})

	s.Group("", func(group *ghttp.RouterGroup) {
		group.Middleware(middleware)

		group.GET("/profile", func(r *ghttp.Request) {
			payload, err := auth.GetPayload(r.Request)
			if err != nil {
				responseFail(r, http.StatusBadRequest, err.Error())
			}

			responseSuccess(r, "success", payload)
		})
	})

	s.SetPort(8888)
	s.Run()
}

func Test_GenerateToken(t *testing.T) {
	token, err := auth.GenerateToken(jwt.Payload{
		"user_id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(token)

	time.Sleep(6 * time.Second)

	token, err = auth.RetreadToken(token.Token)
	if err != nil {
		t.Fatal(err)
	}

	t.Log(token)
}

func Test_Middleware(t *testing.T) {
	token, err := auth.GenerateToken(jwt.Payload{
		"user_id": 1,
	})
	if err != nil {
		t.Fatal(err)
	}

	r, err := http.NewRequest(http.MethodGet, "/", nil)
	if err != nil {
		t.Fatal(err)
	}

	r.Header.Add("Authorization", "Bearer "+token.Token)

	if r, err = auth.Middleware(r); err != nil {
		t.Fatal(err)
	}

	if token, err = auth.RefreshToken(r); err != nil {
		t.Fatal(err)
	}

	payload, err := auth.GetPayload(r)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Log(payload)
	}

	token, err = auth.GetToken(r)
	if err != nil {
		t.Fatal(err)
	} else {
		t.Log(token)
	}
}
