package main_test

import (
    "net/http"
    "testing"
    
    "github.com/gogf/gf/frame/g"
    "github.com/gogf/gf/net/ghttp"
    
    "github.com/dobyte/jwt"
)

type Response struct {
    Status  int         `json:"status"`
    Message string      `json:"message"`
    Data    interface{} `json:"data"`
}

var auth = jwt.NewJwt(&jwt.Options{
    Realm:       "backend",
    Algorithm:   "HS256",
    Secret:      "secret",
    ExpireTime:  3600,
    RefreshTime: 7200,
    TokenLookup: "header:Authorization",
})

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
    if request, err := auth.Middleware(r.Request); err != nil {
        if e, ok := err.(*jwt.Error); ok {
            switch e.Errors {
            case jwt.ErrorExpiredToken:
                responseFail(r, http.StatusUnauthorized, "授权已过期")
            case jwt.ErrorInvalidToken:
                responseFail(r, http.StatusUnauthorized, "无效授权")
            case jwt.ErrorAuthorizeElsewhere:
                responseFail(r, http.StatusUnauthorized, "账号在其它地方登陆")
            }
        }
        
        responseFail(r, http.StatusUnauthorized, "未授权")
    } else {
        r.Request = request
    }
    
    r.Middleware.Next()
}

func Test_Server(t *testing.T) {
    s := g.Server()
    
    s.Group("", func(group *ghttp.RouterGroup) {
        group.POST("/login", func(r *ghttp.Request) {
            token, err := auth.GenerateToken(g.Map{
                "id":      1,
                "account": "fuxiao",
            })
            
            if err != nil {
                responseFail(r, http.StatusBadRequest, "授权失败")
                return
            }
            
            responseSuccess(r, "授权成功", g.Map{
                "type":       token.Type,
                "token":      token.Token,
                "expire_at":  token.ExpireAt,
                "invalid_at": token.InvalidAt,
            })
        })
        
        group.DELETE("/logout", func(r *ghttp.Request) {
            responseSuccess(r, "登出成功", nil)
        })
    })
    
    s.Group("", func(group *ghttp.RouterGroup) {
        group.Middleware(middleware)
        
        group.GET("/profile", func(r *ghttp.Request) {
            responseSuccess(r, "获取成功", g.Map{
                "id":      auth.GetCtxValue(r.Request, "id"),
                "account": auth.GetCtxValue(r.Request, "account"),
            })
        })
        
        group.PUT("/refresh", func(r *ghttp.Request) {
            tokenStr, err := auth.LookupToken(r.Request)
            if err != nil {
                responseFail(r, http.StatusBadRequest, "刷新失败")
                return
            }
            
            token, err := auth.RefreshToken(tokenStr)
            
            if err != nil {
                responseFail(r, http.StatusBadRequest, "刷新失败")
                return
            }
            
            responseSuccess(r, "刷新成功", g.Map{
                "type":       token.Type,
                "token":      token.Token,
                "expire_at":  token.ExpireAt,
                "invalid_at": token.InvalidAt,
            })
        })
    })
    
    s.SetPort(8888)
    s.Run()
}

func Test_GenerateToken(t *testing.T) {
    token, err := auth.GenerateToken(map[string]interface{}{
        "user_id": 1,
    })
    if err != nil {
        t.Error(err)
    }
    
    t.Log(token)
    
    claims, err := auth.ParseToken(token.Token)
    if err != nil {
        t.Error(err)
    }
    
    t.Log(claims)
    
    token, err = auth.RefreshToken(token.Token)
    if err != nil {
        t.Error(err)
    }
    
    t.Log(token)
}