// Code generated by go-swagger; DO NOT EDIT.

package issuer_service

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"encoding/json"
	stderrors "errors"
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"

	"github.com/agntcy/identity/api/client/models"
)

// GetIssuerWellKnownReader is a Reader for the GetIssuerWellKnown structure.
type GetIssuerWellKnownReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *GetIssuerWellKnownReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (any, error) {
	switch response.Code() {
	case 200:
		result := NewGetIssuerWellKnownOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewGetIssuerWellKnownDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewGetIssuerWellKnownOK creates a GetIssuerWellKnownOK with default headers values
func NewGetIssuerWellKnownOK() *GetIssuerWellKnownOK {
	return &GetIssuerWellKnownOK{}
}

/*
GetIssuerWellKnownOK describes a response with status code 200, with default header values.

A successful response.
*/
type GetIssuerWellKnownOK struct {
	Payload *models.V1alpha1GetIssuerWellKnownResponse
}

// IsSuccess returns true when this get issuer well known o k response has a 2xx status code
func (o *GetIssuerWellKnownOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this get issuer well known o k response has a 3xx status code
func (o *GetIssuerWellKnownOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this get issuer well known o k response has a 4xx status code
func (o *GetIssuerWellKnownOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this get issuer well known o k response has a 5xx status code
func (o *GetIssuerWellKnownOK) IsServerError() bool {
	return false
}

// IsCode returns true when this get issuer well known o k response a status code equal to that given
func (o *GetIssuerWellKnownOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the get issuer well known o k response
func (o *GetIssuerWellKnownOK) Code() int {
	return 200
}

func (o *GetIssuerWellKnownOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1alpha1/issuer/{commonName}/.well-known/jwks.json][%d] getIssuerWellKnownOK %s", 200, payload)
}

func (o *GetIssuerWellKnownOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1alpha1/issuer/{commonName}/.well-known/jwks.json][%d] getIssuerWellKnownOK %s", 200, payload)
}

func (o *GetIssuerWellKnownOK) GetPayload() *models.V1alpha1GetIssuerWellKnownResponse {
	return o.Payload
}

func (o *GetIssuerWellKnownOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1alpha1GetIssuerWellKnownResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && !stderrors.Is(err, io.EOF) {
		return err
	}

	return nil
}

// NewGetIssuerWellKnownDefault creates a GetIssuerWellKnownDefault with default headers values
func NewGetIssuerWellKnownDefault(code int) *GetIssuerWellKnownDefault {
	return &GetIssuerWellKnownDefault{
		_statusCode: code,
	}
}

/*
GetIssuerWellKnownDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type GetIssuerWellKnownDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this get issuer well known default response has a 2xx status code
func (o *GetIssuerWellKnownDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this get issuer well known default response has a 3xx status code
func (o *GetIssuerWellKnownDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this get issuer well known default response has a 4xx status code
func (o *GetIssuerWellKnownDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this get issuer well known default response has a 5xx status code
func (o *GetIssuerWellKnownDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this get issuer well known default response a status code equal to that given
func (o *GetIssuerWellKnownDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the get issuer well known default response
func (o *GetIssuerWellKnownDefault) Code() int {
	return o._statusCode
}

func (o *GetIssuerWellKnownDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1alpha1/issuer/{commonName}/.well-known/jwks.json][%d] GetIssuerWellKnown default %s", o._statusCode, payload)
}

func (o *GetIssuerWellKnownDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[GET /v1alpha1/issuer/{commonName}/.well-known/jwks.json][%d] GetIssuerWellKnown default %s", o._statusCode, payload)
}

func (o *GetIssuerWellKnownDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *GetIssuerWellKnownDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && !stderrors.Is(err, io.EOF) {
		return err
	}

	return nil
}
