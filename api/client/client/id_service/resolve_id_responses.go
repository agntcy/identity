// Code generated by go-swagger; DO NOT EDIT.

package id_service

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

// ResolveIDReader is a Reader for the ResolveID structure.
type ResolveIDReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *ResolveIDReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (any, error) {
	switch response.Code() {
	case 200:
		result := NewResolveIDOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	default:
		result := NewResolveIDDefault(response.Code())
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		if response.Code()/100 == 2 {
			return result, nil
		}
		return nil, result
	}
}

// NewResolveIDOK creates a ResolveIDOK with default headers values
func NewResolveIDOK() *ResolveIDOK {
	return &ResolveIDOK{}
}

/*
ResolveIDOK describes a response with status code 200, with default header values.

A successful response.
*/
type ResolveIDOK struct {
	Payload *models.V1alpha1ResolveResponse
}

// IsSuccess returns true when this resolve Id o k response has a 2xx status code
func (o *ResolveIDOK) IsSuccess() bool {
	return true
}

// IsRedirect returns true when this resolve Id o k response has a 3xx status code
func (o *ResolveIDOK) IsRedirect() bool {
	return false
}

// IsClientError returns true when this resolve Id o k response has a 4xx status code
func (o *ResolveIDOK) IsClientError() bool {
	return false
}

// IsServerError returns true when this resolve Id o k response has a 5xx status code
func (o *ResolveIDOK) IsServerError() bool {
	return false
}

// IsCode returns true when this resolve Id o k response a status code equal to that given
func (o *ResolveIDOK) IsCode(code int) bool {
	return code == 200
}

// Code gets the status code for the resolve Id o k response
func (o *ResolveIDOK) Code() int {
	return 200
}

func (o *ResolveIDOK) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1alpha1/id/resolve][%d] resolveIdOK %s", 200, payload)
}

func (o *ResolveIDOK) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1alpha1/id/resolve][%d] resolveIdOK %s", 200, payload)
}

func (o *ResolveIDOK) GetPayload() *models.V1alpha1ResolveResponse {
	return o.Payload
}

func (o *ResolveIDOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.V1alpha1ResolveResponse)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && !stderrors.Is(err, io.EOF) {
		return err
	}

	return nil
}

// NewResolveIDDefault creates a ResolveIDDefault with default headers values
func NewResolveIDDefault(code int) *ResolveIDDefault {
	return &ResolveIDDefault{
		_statusCode: code,
	}
}

/*
ResolveIDDefault describes a response with status code -1, with default header values.

An unexpected error response.
*/
type ResolveIDDefault struct {
	_statusCode int

	Payload *models.RPCStatus
}

// IsSuccess returns true when this resolve Id default response has a 2xx status code
func (o *ResolveIDDefault) IsSuccess() bool {
	return o._statusCode/100 == 2
}

// IsRedirect returns true when this resolve Id default response has a 3xx status code
func (o *ResolveIDDefault) IsRedirect() bool {
	return o._statusCode/100 == 3
}

// IsClientError returns true when this resolve Id default response has a 4xx status code
func (o *ResolveIDDefault) IsClientError() bool {
	return o._statusCode/100 == 4
}

// IsServerError returns true when this resolve Id default response has a 5xx status code
func (o *ResolveIDDefault) IsServerError() bool {
	return o._statusCode/100 == 5
}

// IsCode returns true when this resolve Id default response a status code equal to that given
func (o *ResolveIDDefault) IsCode(code int) bool {
	return o._statusCode == code
}

// Code gets the status code for the resolve Id default response
func (o *ResolveIDDefault) Code() int {
	return o._statusCode
}

func (o *ResolveIDDefault) Error() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1alpha1/id/resolve][%d] ResolveId default %s", o._statusCode, payload)
}

func (o *ResolveIDDefault) String() string {
	payload, _ := json.Marshal(o.Payload)
	return fmt.Sprintf("[POST /v1alpha1/id/resolve][%d] ResolveId default %s", o._statusCode, payload)
}

func (o *ResolveIDDefault) GetPayload() *models.RPCStatus {
	return o.Payload
}

func (o *ResolveIDDefault) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	o.Payload = new(models.RPCStatus)

	// response payload
	if err := consumer.Consume(response.Body(), o.Payload); err != nil && !stderrors.Is(err, io.EOF) {
		return err
	}

	return nil
}
