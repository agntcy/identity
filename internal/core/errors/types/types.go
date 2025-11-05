// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

//go:generate stringer -type=ErrorReason

//nolint:errname // Ignore error name for types/proto
package types

import (
	"errors"
	"fmt"
)

// Represents the reason for an error, providing a unique
// constant value for the error.
type ErrorReason int

const (
	// ERROR_REASON_UNSPECIFIED indicates that no specific error reason
	// has been specified.
	ERROR_REASON_UNSPECIFIED ErrorReason = iota

	// An internal error, this happens in case of unexpected condition or failure within the service
	ERROR_REASON_INTERNAL

	// The credential envelope type is invalid. For valid values refer to
	// the enum CredentialEnvelopeType.
	ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE

	// The credential envelope value format does not correspond to the format
	// specified in envelope_type.
	ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT

	// The issuer contains one or more invalid fields.
	ERROR_REASON_INVALID_ISSUER

	// The issuer is not registered in the Node.
	ERROR_REASON_ISSUER_NOT_REGISTERED

	// The Verifiable Credential is invalid, this can be related to either
	// invalid format or unable to verify the Data Integrity proof.
	ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL

	// The Identity Provider (IdP) is required for the operation, but it is not provided.
	ERROR_REASON_IDP_REQUIRED

	// The proof is invalid
	ERROR_REASON_INVALID_PROOF

	// The proof type is not supported
	ERROR_REASON_UNSUPPORTED_PROOF

	// Unable to resolve an ID to a ResolverMetadata
	ERROR_REASON_RESOLVER_METADATA_NOT_FOUND

	// Unknown Identity Provider
	ERROR_REASON_UNKNOWN_IDP

	// The ID and Resolver Metadata are already registered in the system
	ERROR_REASON_ID_ALREADY_REGISTERED

	// The Verifiable Credential is revoked
	ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED
)

// Describes the cause of the error with structured details.
type ErrorInfo struct {
	// The reason of the error, as defined by the ErrorReason enum.
	// This is a constant unique value that helps identify the cause of
	// the error.
	Reason ErrorReason `json:"reason,omitempty"`

	// The message describing the error in a human-readable way. This
	// field gives additional details about the error.
	Message string `json:"message,omitempty"`

	// The underlying error if present
	Err error `json:"-" protobuf:"-"`
}

func (err ErrorInfo) Error() string {
	return fmt.Sprintf("%s (reason: %s)", err.Message, err.Reason.String())
}

func IsErrorInfo(err error, reason ErrorReason) bool {
	var errInfo ErrorInfo
	if errors.As(err, &errInfo) {
		return errInfo.Reason == reason
	}

	return false
}

func AsErrorInfo(err error) *ErrorInfo {
	var errInfo ErrorInfo
	if errors.As(err, &errInfo) {
		return &errInfo
	}

	return nil
}
