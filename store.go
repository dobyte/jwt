/**
 * @Author: fuxiao
 * @Author: 576101059@qq.com
 * @Date: 2021/11/30 10:59
 * @Desc: TODO
 */

package jwt

import (
	"context"
	"time"
)

type (
	Store interface {
		Get(ctx context.Context, key interface{}) (interface{}, error)

		Set(ctx context.Context, key interface{}, value interface{}, duration time.Duration) error

		Remove(ctx context.Context, keys ...interface{}) (value interface{}, err error)
	}
)
