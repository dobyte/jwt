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
		Get(ctx context.Context, key any) (any, error)

		Set(ctx context.Context, key any, value any, duration time.Duration) error

		Remove(ctx context.Context, keys ...any) (value any, err error)
	}
)
