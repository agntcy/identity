// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package converters

import (
	coreapi "github.com/agntcy/identity/api/server/agntcy/identity/core/v1alpha1"
	errtypes "github.com/agntcy/identity/internal/core/errors/types"
	"github.com/agntcy/identity/internal/pkg/ptrutil"
)

func FromErrorInfo(src *errtypes.ErrorInfo) *coreapi.ErrorInfo {
	if src == nil {
		return nil
	}

	return &coreapi.ErrorInfo{
		Reason:  ptrutil.Ptr(coreapi.ErrorReason(src.Reason)),
		Message: &src.Message,
	}
}
