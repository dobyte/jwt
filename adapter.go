/**
 * @Author: wanglin
 * @Author: wanglin@vspn.com
 * @Date: 2021/11/30 10:59
 * @Desc: TODO
 */

package jwt

import (
	"context"
	"time"
)

type (
	Adapter interface {
		Get(ctx context.Context, key interface{}) (interface{}, error)

		Set(ctx context.Context, key interface{}, value interface{}, duration time.Duration) error

		Remove(ctx context.Context, keys ...interface{}) (value interface{}, err error)
	}
)
