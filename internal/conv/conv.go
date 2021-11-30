/**
 * @Author: fuxiao
 * @Email: 576101059@qq.com
 * @Date: 2021/5/26 12:41 下午
 * @Desc: TODO
 */

package conv

import (
	"encoding"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"time"
)

func String(any interface{}) string {
	switch v := any.(type) {
	case nil:
		return ""
	case string:
		return v
	case int:
		return strconv.Itoa(v)
	case int8:
		return strconv.Itoa(int(v))
	case int16:
		return strconv.Itoa(int(v))
	case int32:
		return strconv.Itoa(int(v))
	case int64:
		return strconv.FormatInt(v, 10)
	case uint:
		return strconv.FormatUint(uint64(v), 10)
	case uint8:
		return strconv.FormatUint(uint64(v), 10)
	case uint16:
		return strconv.FormatUint(uint64(v), 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	case []byte:
		return string(v)
	case time.Time:
		return v.String()
	case *time.Time:
		if v == nil {
			return ""
		}
		return v.String()
	default:
		if v == nil {
			return ""
		}

		if i, ok := v.(stringInterface); ok {
			return i.String()
		}

		if i, ok := v.(errorInterface); ok {
			return i.Error()
		}

		var (
			rv   = reflect.ValueOf(v)
			kind = rv.Kind()
		)

		switch kind {
		case reflect.Chan,
			reflect.Map,
			reflect.Slice,
			reflect.Func,
			reflect.Ptr,
			reflect.Interface,
			reflect.UnsafePointer:
			if rv.IsNil() {
				return ""
			}
		case reflect.String:
			return rv.String()
		}

		if kind == reflect.Ptr {
			return String(rv.Elem().Interface())
		}

		if b, e := json.Marshal(v); e != nil {
			return fmt.Sprint(v)
		} else {
			return string(b)
		}
	}
}

func Scan(b []byte, any interface{}) error {
	switch v := any.(type) {
	case nil:
		return fmt.Errorf("cache: Scan(nil)")
	case *string:
		*v = String(b)
		return nil
	case *[]byte:
		*v = b
		return nil
	case *int:
		var err error
		*v, err = strconv.Atoi(String(b))
		return err
	case *int8:
		n, err := strconv.ParseInt(String(b), 10, 8)
		if err != nil {
			return err
		}
		*v = int8(n)
		return nil
	case *int16:
		n, err := strconv.ParseInt(String(b), 10, 16)
		if err != nil {
			return err
		}
		*v = int16(n)
		return nil
	case *int32:
		n, err := strconv.ParseInt(String(b), 10, 32)
		if err != nil {
			return err
		}
		*v = int32(n)
		return nil
	case *int64:
		n, err := strconv.ParseInt(String(b), 10, 64)
		if err != nil {
			return err
		}
		*v = n
		return nil
	case *uint:
		n, err := strconv.ParseUint(String(b), 10, 64)
		if err != nil {
			return err
		}
		*v = uint(n)
		return nil
	case *uint8:
		n, err := strconv.ParseUint(String(b), 10, 8)
		if err != nil {
			return err
		}
		*v = uint8(n)
		return nil
	case *uint16:
		n, err := strconv.ParseUint(String(b), 10, 16)
		if err != nil {
			return err
		}
		*v = uint16(n)
		return nil
	case *uint32:
		n, err := strconv.ParseUint(String(b), 10, 32)
		if err != nil {
			return err
		}
		*v = uint32(n)
		return nil
	case *uint64:
		n, err := strconv.ParseUint(String(b), 10, 64)
		if err != nil {
			return err
		}
		*v = n
		return nil
	case *float32:
		n, err := strconv.ParseFloat(String(b), 32)
		if err != nil {
			return err
		}
		*v = float32(n)
		return err
	case *float64:
		var err error
		*v, err = strconv.ParseFloat(String(b), 64)
		return err
	case *bool:
		*v = len(b) == 1 && b[0] == '1'
		return nil
	case *time.Time:
		var err error
		*v, err = time.Parse(time.RFC3339Nano, String(b))
		return err
	case encoding.BinaryUnmarshaler:
		return v.UnmarshalBinary(b)
	default:
		var (
			rv   = reflect.ValueOf(v)
			kind = rv.Kind()
		)

		if kind != reflect.Ptr {
			return fmt.Errorf("can't unmarshal %T", v)
		}

		switch kind = rv.Elem().Kind(); kind {
		case reflect.Array, reflect.Slice, reflect.Map, reflect.Struct:
			return json.Unmarshal(b, v)
		}

		return fmt.Errorf("can't unmarshal %T", v)
	}
}
