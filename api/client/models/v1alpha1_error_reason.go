// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"encoding/json"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/validate"
)

// V1alpha1ErrorReason Represents the reason for an error, providing a unique
// constant value for the error.
//
//   - ERROR_REASON_UNSPECIFIED: ERROR_REASON_UNSPECIFIED indicates that no specific error reason
//
// has been specified.
//   - ERROR_REASON_INTERNAL: An internal error, this happens in case of unexpected condition or failure within the service
//   - ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE: The credential envelope type is invalid. For valid values refer to
//
// the enum CredentialEnvelopeType.
//   - ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT: The credential envelope value format does not correspond to the format
//
// specified in envelope_type.
//   - ERROR_REASON_INVALID_ISSUER: The issuer contains one or more invalid fields.
//   - ERROR_REASON_ISSUER_NOT_REGISTERED: The issuer is not registered in the Node.
//   - ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL: The Verifiable Credential is invalid, this can be related to either
//
// invalid format or unable to verify the Data Integrity proof.
//   - ERROR_REASON_IDP_REQUIRED: The Identity Provider (IdP) is required for the operation, but it is not provided.
//   - ERROR_REASON_INVALID_PROOF: The proof is invalid
//   - ERROR_REASON_UNSUPPORTED_PROOF: The proof type is not supported
//   - ERROR_REASON_RESOLVER_METADATA_NOT_FOUND: Unable to resolve an ID to a ResolverMetadata
//   - ERROR_REASON_UNKNOWN_IDP: Unknown Identity Provider
//   - ERROR_REASON_ID_ALREADY_REGISTERED: The ID and Resolver Metadata are already registered in the system
//   - ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED: The Verifiable Credential is revoked
//
// swagger:model v1alpha1ErrorReason
type V1alpha1ErrorReason string

func NewV1alpha1ErrorReason(value V1alpha1ErrorReason) *V1alpha1ErrorReason {
	return &value
}

// Pointer returns a pointer to a freshly-allocated V1alpha1ErrorReason.
func (m V1alpha1ErrorReason) Pointer() *V1alpha1ErrorReason {
	return &m
}

const (

	// V1alpha1ErrorReasonERRORREASONUNSPECIFIED captures enum value "ERROR_REASON_UNSPECIFIED"
	V1alpha1ErrorReasonERRORREASONUNSPECIFIED V1alpha1ErrorReason = "ERROR_REASON_UNSPECIFIED"

	// V1alpha1ErrorReasonERRORREASONINTERNAL captures enum value "ERROR_REASON_INTERNAL"
	V1alpha1ErrorReasonERRORREASONINTERNAL V1alpha1ErrorReason = "ERROR_REASON_INTERNAL"

	// V1alpha1ErrorReasonERRORREASONINVALIDCREDENTIALENVELOPETYPE captures enum value "ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE"
	V1alpha1ErrorReasonERRORREASONINVALIDCREDENTIALENVELOPETYPE V1alpha1ErrorReason = "ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE"

	// V1alpha1ErrorReasonERRORREASONINVALIDCREDENTIALENVELOPEVALUEFORMAT captures enum value "ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT"
	V1alpha1ErrorReasonERRORREASONINVALIDCREDENTIALENVELOPEVALUEFORMAT V1alpha1ErrorReason = "ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT"

	// V1alpha1ErrorReasonERRORREASONINVALIDISSUER captures enum value "ERROR_REASON_INVALID_ISSUER"
	V1alpha1ErrorReasonERRORREASONINVALIDISSUER V1alpha1ErrorReason = "ERROR_REASON_INVALID_ISSUER"

	// V1alpha1ErrorReasonERRORREASONISSUERNOTREGISTERED captures enum value "ERROR_REASON_ISSUER_NOT_REGISTERED"
	V1alpha1ErrorReasonERRORREASONISSUERNOTREGISTERED V1alpha1ErrorReason = "ERROR_REASON_ISSUER_NOT_REGISTERED"

	// V1alpha1ErrorReasonERRORREASONINVALIDVERIFIABLECREDENTIAL captures enum value "ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL"
	V1alpha1ErrorReasonERRORREASONINVALIDVERIFIABLECREDENTIAL V1alpha1ErrorReason = "ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL"

	// V1alpha1ErrorReasonERRORREASONIDPREQUIRED captures enum value "ERROR_REASON_IDP_REQUIRED"
	V1alpha1ErrorReasonERRORREASONIDPREQUIRED V1alpha1ErrorReason = "ERROR_REASON_IDP_REQUIRED"

	// V1alpha1ErrorReasonERRORREASONINVALIDPROOF captures enum value "ERROR_REASON_INVALID_PROOF"
	V1alpha1ErrorReasonERRORREASONINVALIDPROOF V1alpha1ErrorReason = "ERROR_REASON_INVALID_PROOF"

	// V1alpha1ErrorReasonERRORREASONUNSUPPORTEDPROOF captures enum value "ERROR_REASON_UNSUPPORTED_PROOF"
	V1alpha1ErrorReasonERRORREASONUNSUPPORTEDPROOF V1alpha1ErrorReason = "ERROR_REASON_UNSUPPORTED_PROOF"

	// V1alpha1ErrorReasonERRORREASONRESOLVERMETADATANOTFOUND captures enum value "ERROR_REASON_RESOLVER_METADATA_NOT_FOUND"
	V1alpha1ErrorReasonERRORREASONRESOLVERMETADATANOTFOUND V1alpha1ErrorReason = "ERROR_REASON_RESOLVER_METADATA_NOT_FOUND"

	// V1alpha1ErrorReasonERRORREASONUNKNOWNIDP captures enum value "ERROR_REASON_UNKNOWN_IDP"
	V1alpha1ErrorReasonERRORREASONUNKNOWNIDP V1alpha1ErrorReason = "ERROR_REASON_UNKNOWN_IDP"

	// V1alpha1ErrorReasonERRORREASONIDALREADYREGISTERED captures enum value "ERROR_REASON_ID_ALREADY_REGISTERED"
	V1alpha1ErrorReasonERRORREASONIDALREADYREGISTERED V1alpha1ErrorReason = "ERROR_REASON_ID_ALREADY_REGISTERED"

	// V1alpha1ErrorReasonERRORREASONVERIFIABLECREDENTIALREVOKED captures enum value "ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED"
	V1alpha1ErrorReasonERRORREASONVERIFIABLECREDENTIALREVOKED V1alpha1ErrorReason = "ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED"
)

// for schema
var v1alpha1ErrorReasonEnum []any

func init() {
	var res []V1alpha1ErrorReason
	if err := json.Unmarshal([]byte(`["ERROR_REASON_UNSPECIFIED","ERROR_REASON_INTERNAL","ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_TYPE","ERROR_REASON_INVALID_CREDENTIAL_ENVELOPE_VALUE_FORMAT","ERROR_REASON_INVALID_ISSUER","ERROR_REASON_ISSUER_NOT_REGISTERED","ERROR_REASON_INVALID_VERIFIABLE_CREDENTIAL","ERROR_REASON_IDP_REQUIRED","ERROR_REASON_INVALID_PROOF","ERROR_REASON_UNSUPPORTED_PROOF","ERROR_REASON_RESOLVER_METADATA_NOT_FOUND","ERROR_REASON_UNKNOWN_IDP","ERROR_REASON_ID_ALREADY_REGISTERED","ERROR_REASON_VERIFIABLE_CREDENTIAL_REVOKED"]`), &res); err != nil {
		panic(err)
	}
	for _, v := range res {
		v1alpha1ErrorReasonEnum = append(v1alpha1ErrorReasonEnum, v)
	}
}

func (m V1alpha1ErrorReason) validateV1alpha1ErrorReasonEnum(path, location string, value V1alpha1ErrorReason) error {
	if err := validate.EnumCase(path, location, value, v1alpha1ErrorReasonEnum, true); err != nil {
		return err
	}
	return nil
}

// Validate validates this v1alpha1 error reason
func (m V1alpha1ErrorReason) Validate(formats strfmt.Registry) error {
	var res []error

	// value enum
	if err := m.validateV1alpha1ErrorReasonEnum("", "body", m); err != nil {
		return err
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// ContextValidate validates this v1alpha1 error reason based on context it is used
func (m V1alpha1ErrorReason) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	return nil
}
