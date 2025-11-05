// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package convertutil

import (
	"encoding/json"
	"reflect"

	"github.com/agntcy/identity/internal/pkg/log"
)

func Convert[D any](src any) *D {
	if isNilish(src) {
		return nil
	}

	var dst D
	if deepCopy(src, &dst) != nil {
		return nil
	}

	return &dst
}

func ConvertSlice[T any, S any](list []T, convert func(T) *S) []*S {
	var responseList = make([]*S, 0)
	for _, obj := range list {
		responseList = append(responseList, convert(obj))
	}

	return responseList
}

func isNilish(val any) bool {
	if val == nil {
		return true
	}

	v := reflect.ValueOf(val)
	k := v.Kind()

	//nolint:exhaustive // Ignore exhaustive check
	switch k {
	case reflect.Chan, reflect.Func, reflect.Map, reflect.Pointer,
		reflect.UnsafePointer, reflect.Interface, reflect.Slice:
		return v.IsNil()
	}

	return false
}

func deepCopy(src, dst interface{}) error {
	data, err := json.Marshal(src)
	if err != nil {
		log.Warn(err)
		return err
	}

	err = json.Unmarshal(data, dst)
	if err != nil {
		log.Warn(err)
		return err
	}

	return nil
}
