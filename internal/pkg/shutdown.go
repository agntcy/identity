// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package pkg

import (
	"context"
	"errors"
)

func ShutdownWithContext(
	ctx context.Context,
	gracefulShutdownFunc func(ctx context.Context) error,
	forceShutdownFunc func() error,
) error {
	errCh := make(chan error, 1)

	go func() {
		errCh <- gracefulShutdownFunc(ctx)
	}()

	// Wait for the context to be done (timeout, cancel, ...) or shutdownFunc to complete
	select {
	case <-ctx.Done():
		err := ctx.Err()

		if forceShutdownFunc != nil {
			err = errors.Join(err, forceShutdownFunc())
		}

		return err
	case err := <-errCh:
		return err
	}
}
