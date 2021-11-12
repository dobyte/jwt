/**
 * @Author: wanglin
 * @Author: wanglin@vspn.com
 * @Date: 2021/11/12 17:20
 * @Desc: TODO
 */

package main

import (
	"testing"

	"github.com/dobyte/jwt"
)

func TestNewAuth(t *testing.T) {
	var auth, _ = jwt.NewAuth(&jwt.AuthOptions{
		jwt.Options{
			Issuer:      "backend",
			SignMethod:  jwt.HS256,
			SecretKey:   "secret",
			ExpiredTime: 3600,
			Locations:   "header:Authorization",
		},
	})

	token, err := auth.GenerateToken("1")
	if err != nil {
		t.Fatal(err)
	}

	t.Log(token)
}
