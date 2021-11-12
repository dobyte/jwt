/**
 * @Author: wanglin
 * @Author: wanglin@vspn.com
 * @Date: 2021/11/12 16:22
 * @Desc: TODO
 */

package jwt

type (
	Cache interface {
		Get(key string) (string, error)
		Set(key string, value string) error
		Delete(key string) error
	}
)
