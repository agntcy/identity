// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//nolint:testpackage // contextLogFieldsKey needs to be accessed by the tests
package log

import (
	"context"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestEnrichContext(t *testing.T) {
	t.Parallel()

	t.Run("should add context log fields to ctx when not existing", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		ctx = EnrichContext(ctx, logrus.Fields{
			"key1": "value1",
			"key2": "value2",
		})

		fields := ctx.Value(contextLogFieldsKey{})

		assert.Equal(t, logrus.Fields{
			"key1": "value1",
			"key2": "value2",
		}, fields)
	})

	t.Run("should replace context log fields when already existing in ctx", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		ctx = EnrichContext(ctx, logrus.Fields{
			"key": "old",
		})

		fields := ctx.Value(contextLogFieldsKey{})

		assert.Equal(t, logrus.Fields{
			"key": "old",
		}, fields)

		ctx = EnrichContext(ctx, logrus.Fields{
			"key": "new",
		})

		fields = ctx.Value(contextLogFieldsKey{})

		assert.Equal(t, logrus.Fields{
			"key": "new",
		}, fields)
	})
}
