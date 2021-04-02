package main

import (
	"github.com/dobyte/gf-jwt"
	"github.com/gogf/gf/frame/g"
	"github.com/gogf/gf/net/ghttp"
	"log"
	"net/http"
	"time"
)

type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
}

var jwtAuth *jwt.Jwt

func init() {
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

	jwtAuth = auth
}

func responseFail(r *ghttp.Request, status int, message string) {
	_ = r.Response.WriteJsonExit(Response{
		Status:  status,
		Message: message,
	})
}

func responseSuccess(r *ghttp.Request, message string, data g.Map) {
	_ = r.Response.WriteJsonExit(Response{
		Status:  http.StatusOK,
		Message: message,
		Data:    data,
	})
}

func middleware(r *ghttp.Request) {
	if err := jwtAuth.Middleware(r); err != nil {
		if e, ok := err.(*jwt.Error); ok {
			switch e.Errors {
			case jwt.ErrorExpiredToken:
				responseFail(r, http.StatusUnauthorized, "授权已过期")
			case jwt.ErrorMissingExpField, jwt.ErrorWrongFormatOfExp:
				responseFail(r, http.StatusUnauthorized, "无效授权")
			case jwt.ErrorAuthorizeElsewhere:
				responseFail(r, http.StatusUnauthorized, "账号在其它地方登陆")
			}
		}

		responseFail(r, http.StatusUnauthorized, "未授权")
	}

	r.Middleware.Next()
}

func main() {
	s := g.Server()

	s.Group("", func(group *ghttp.RouterGroup) {
		group.POST("/login", func(r *ghttp.Request) {
			token, err := jwtAuth.GenerateToken(g.Map{
				"id":      1,
				"account": "fuxiao",
			})

			if err != nil {
				responseFail(r, http.StatusBadRequest, "授权失败")
				return
			}

			responseSuccess(r, "授权成功", g.Map{
				"type":   token.Type,
				"token":  token.Token,
				"expire": token.Expire,
			})
		})

		group.DELETE("/logout", func(r *ghttp.Request) {
			err := jwtAuth.DestroyToken(r)

			if err != nil {
				responseFail(r, http.StatusBadRequest, "登出失败")
				return
			}

			responseSuccess(r, "登出成功", nil)
		})
	})

	s.Group("", func(group *ghttp.RouterGroup) {
		group.Middleware(middleware)

		group.GET("/profile", func(r *ghttp.Request) {
			claims, err := jwtAuth.GetClaims(r)

			if err != nil {
				responseFail(r, http.StatusBadRequest, "参数失败")
				return
			}

			responseSuccess(r, "获取成功", g.Map{
				"identity": jwtAuth.GetIdentity(r),
				"id":       claims["id"],
				"account":  claims["account"],
			})
		})

		group.PUT("/refresh", func(r *ghttp.Request) {
			token, err := jwtAuth.RefreshToken(r)

			if err != nil {
				responseFail(r, http.StatusBadRequest, "刷新失败")
				return
			}

			responseSuccess(r, "刷新成功", g.Map{
				"type":   token.Type,
				"token":  token.Token,
				"expire": token.Expire,
			})
		})
	})

	s.SetPort(8888)
	s.Run()
}
