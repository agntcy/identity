// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package errutil

import (
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
)

func ErrInfo(reason errtypes.ErrorReason, message string, err error) errtypes.ErrorInfo {
	return errtypes.ErrorInfo{
		Reason:  reason,
		Message: message,
		Err:     err,
	}
}
