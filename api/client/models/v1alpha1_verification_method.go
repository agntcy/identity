// Code generated by go-swagger; DO NOT EDIT.

package models

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	stderrors "errors"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
)

// V1alpha1VerificationMethod VerificationMethod expresses verification methods, such as cryptographic
// public keys, which can be used to authenticate or authorize interactions
// with the entities represented by the ID. It is a part of the ResolverMetadata.
//
// swagger:model v1alpha1VerificationMethod
type V1alpha1VerificationMethod struct {

	// A unique id of the verification method.
	ID string `json:"id,omitempty"`

	// The public key used for the verification method.
	PublicKeyJwk *V1alpha1Jwk `json:"publicKeyJwk,omitempty"`
}

// Validate validates this v1alpha1 verification method
func (m *V1alpha1VerificationMethod) Validate(formats strfmt.Registry) error {
	var res []error

	if err := m.validatePublicKeyJwk(formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1alpha1VerificationMethod) validatePublicKeyJwk(formats strfmt.Registry) error {
	if swag.IsZero(m.PublicKeyJwk) { // not required
		return nil
	}

	if m.PublicKeyJwk != nil {
		if err := m.PublicKeyJwk.Validate(formats); err != nil {
			ve := new(errors.Validation)
			if stderrors.As(err, &ve) {
				return ve.ValidateName("publicKeyJwk")
			}
			ce := new(errors.CompositeError)
			if stderrors.As(err, &ce) {
				return ce.ValidateName("publicKeyJwk")
			}

			return err
		}
	}

	return nil
}

// ContextValidate validate this v1alpha1 verification method based on the context it is used
func (m *V1alpha1VerificationMethod) ContextValidate(ctx context.Context, formats strfmt.Registry) error {
	var res []error

	if err := m.contextValidatePublicKeyJwk(ctx, formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

func (m *V1alpha1VerificationMethod) contextValidatePublicKeyJwk(ctx context.Context, formats strfmt.Registry) error {

	if m.PublicKeyJwk != nil {

		if swag.IsZero(m.PublicKeyJwk) { // not required
			return nil
		}

		if err := m.PublicKeyJwk.ContextValidate(ctx, formats); err != nil {
			ve := new(errors.Validation)
			if stderrors.As(err, &ve) {
				return ve.ValidateName("publicKeyJwk")
			}
			ce := new(errors.CompositeError)
			if stderrors.As(err, &ce) {
				return ce.ValidateName("publicKeyJwk")
			}

			return err
		}
	}

	return nil
}

// MarshalBinary interface implementation
func (m *V1alpha1VerificationMethod) MarshalBinary() ([]byte, error) {
	if m == nil {
		return nil, nil
	}
	return swag.WriteJSON(m)
}

// UnmarshalBinary interface implementation
func (m *V1alpha1VerificationMethod) UnmarshalBinary(b []byte) error {
	var res V1alpha1VerificationMethod
	if err := swag.ReadJSON(b, &res); err != nil {
		return err
	}
	*m = res
	return nil
}
