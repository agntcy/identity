// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package errutil

import (
	"errors"

	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/pkg/log"
)

func Err(err error, customMessage string) error {
	// Print en error to the log
	log.Error(customMessage, ": ", err)

	// If there is a custom message, return it
	if customMessage != "" {
		return errors.New(customMessage)
	}

	// Otherwise, return the error
	return err
}

func ErrInfo(reason errtypes.ErrorReason, message string, err error) errtypes.ErrorInfo {
	return errtypes.ErrorInfo{
		Reason:  reason,
		Message: message,
		Err:     err,
	}
}
