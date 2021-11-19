package schema

import (
	"fmt"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/qri-io/jsonschema"
)

type ValidationErrorType string

func NewValidationError(keyError jsonschema.KeyError, errorType schemav1.ErrorType) *ValidationError {
	return &ValidationError{
		Path:    keyError.PropertyPath,
		Message: keyError.Message,
		Type:    errorType,
	}
}

func NewValidationErrorList(errors []jsonschema.KeyError, errorType schemav1.ErrorType) *ValidationErrorList {
	var validationErrorList []ValidationError
	for _, value := range errors {
		validationError := NewValidationError(value, errorType)
		validationErrorList = append(validationErrorList, *validationError)
	}

	return &ValidationErrorList{
		Errors: validationErrorList,
	}
}

func MergeValidationErrorLists(validationErrors ...*ValidationErrorList) *ValidationErrorList {
	noOfErrors := 0
	for _, validationErrorList := range validationErrors {
		noOfErrors += len(validationErrorList.Errors)
	}

	var errors = make([]ValidationError, 0, noOfErrors)

	for _, validationErrorList := range validationErrors {
		for _, validationError := range validationErrorList.Errors {
			errors = append(errors, validationError)
		}
	}

	return &ValidationErrorList{
		Errors: errors,
	}
}

func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}

func IsValidationErrorList(err error) bool {
	_, ok := err.(*ValidationErrorList)
	return ok
}

type ValidationError struct {
	Path    string
	Message string
	Type    schemav1.ErrorType
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

type ValidationErrorList struct {
	Errors []ValidationError
}

func (e *ValidationErrorList) Error() string {
	var errorString = ""
	for _, value := range e.Errors {
		errorString += fmt.Sprintf("%s\n", value.Error())
	}

	return errorString
}

func (e *ValidationErrorList) SchemaErrors() []*schemav1.Error {
	noOfErrors := len(e.Errors)
	if noOfErrors == 0 {
		return nil
	}

	var schemaErrors = make([]*schemav1.Error, 0, noOfErrors)
	for _, validationError := range e.Errors {
		schemaErrors = append(schemaErrors, &schemav1.Error{
			Path:    validationError.Path,
			Message: validationError.Message,
			Type:    validationError.Type,
		})
	}

	return schemaErrors
}
