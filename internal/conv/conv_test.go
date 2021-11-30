/**
 * @Author: wanglin
 * @Email: wanglin@vspn.com
 * @Date: 2021/6/5 11:37 上午
 * @Desc: TODO
 */

package conv_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/dobyte/cache/internal/conv"
)

type student struct {
	Name     string `json:"name"`
	Age      int    `json:"age"`
	Birthday string `json:"birthday"`
}

func TestBytesToString(t *testing.T) {
	b := []byte("abcdefg")

	fmt.Println(b)

	fmt.Println(conv.String(b))
	// fmt.Println(conv.BytesToString(b))
}

func TestScan(t *testing.T) {
	var lucy student

	bytes, _ := json.Marshal(student{Name: "yuebanfuxiao"})

	if err := conv.Scan(bytes, &lucy); err != nil {
		t.Error(err)
	}

	bytes, _ = json.Marshal([]student{
		{
			Name: "lucy",
		},
		{
			Name: "tom",
		},
	})

	t.Log(lucy.Name)

	var group []student

	if err := conv.Scan(bytes, &group); err != nil {
		t.Error(err)
	}

	t.Log(group)
}
