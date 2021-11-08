/**
 * @Author: fuxiao
 * @Email: 576101059@qq.com
 * @Date: 2021/11/7 10:28 上午
 * @Desc: TODO
 */

package jwt_test

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestNewJwt(t *testing.T) {
	filepath := "/Users/fuxiao/Documents/Golang/dobyte/jwt/conf/ccc.pem"

	fileInfo1, err := os.Stat(filepath)
	if err != nil {
		t.Fatal(err)
	}

	fileInfo2, err := os.Lstat(filepath)
	if err != nil {
		t.Fatal(err)
	}

	b, err := ioutil.ReadFile(filepath)

	fmt.Printf("%+v", fileInfo1)
	fmt.Println()
	fmt.Printf("%+v", fileInfo2)
	fmt.Println()
	fmt.Println(b)
}
