// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package identitycache

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/gob"

	"github.com/agntcy/identity/pkg/log"
	"github.com/eko/gocache/lib/v4/cache"
)

// Get from cache
func GetFromCache[T interface{}](
	ctx context.Context,
	tCache *cache.Cache[[]byte],
	key string,
) (*T, bool) {
	// Encode the key
	shaKey := sha256.Sum256([]byte(key))

	if rawBytes, err := tCache.Get(ctx, shaKey); err == nil {
		log.Debug("Using cached value for key")

		// Decode the result
		var cachedEntry T

		decoder := gob.NewDecoder(bytes.NewBuffer(rawBytes))

		decodeErr := decoder.Decode(&cachedEntry)
		if decodeErr == nil {
			return &cachedEntry, true
		}

		return nil, false
	}

	return nil, false
}

// Add to cache
func AddToCache[T interface{}](
	ctx context.Context,
	tCache *cache.Cache[[]byte],
	key string,
	value *T,
) error {
	var rawTCache bytes.Buffer

	encoder := gob.NewEncoder(&rawTCache)

	// Encode the value
	encodeErr := encoder.Encode(value)
	if encodeErr != nil {
		return encodeErr
	}

	// Encode the key
	shaKey := sha256.Sum256([]byte(key))

	setErr := tCache.Set(ctx, shaKey, rawTCache.Bytes())
	if setErr != nil {
		return setErr
	}

	return nil
}
