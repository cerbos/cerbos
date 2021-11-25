package schema

import (
	"fmt"
	schemav1 "github.com/cerbos/cerbos/api/genpb/cerbos/schema/v1"
	"github.com/qri-io/jsonschema"
	"strings"
)

type ValidationErrorType string

func NewValidationError(keyError jsonschema.KeyError, source schemav1.ValidationError_Source) ValidationError {
	return ValidationError{
		Path:    keyError.PropertyPath,
		Message: keyError.Message,
		Source:  source,
	}
}

func NewValidationErrorList(errors []jsonschema.KeyError, source schemav1.ValidationError_Source) ValidationErrorList {
	var validationErrorList []ValidationError
	for _, value := range errors {
		validationError := NewValidationError(value, source)
		validationErrorList = append(validationErrorList, validationError)
	}

	return validationErrorList
}

func MergeValidationErrorLists(validationErrors ...ValidationErrorList) ValidationErrorList {
	var errors []ValidationError
	for _, validationErrorList := range validationErrors {
		for _, validationError := range validationErrorList {
			errors = append(errors, validationError)
		}
	}

	return errors
}

func IsValidationError(err error) bool {
	_, ok := err.(ValidationError)
	return ok
}

func IsValidationErrorList(err error) bool {
	_, ok := err.(ValidationErrorList)
	return ok
}

type ValidationError struct {
	Path    string
	Message string
	Source  schemav1.ValidationError_Source
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

type ValidationErrorList []ValidationError

func (e ValidationErrorList) Error() string {
	var errorString strings.Builder
	for _, value := range e {
		errorString.WriteString(value.Error())
		errorString.WriteString("\n")
	}
	return errorString.String()
}

func (e ValidationErrorList) SchemaErrors() []*schemav1.ValidationError {
	noOfErrors := len(e)
	if noOfErrors == 0 {
		return nil
	}

	var schemaErrors = make([]*schemav1.ValidationError, noOfErrors, noOfErrors)
	for i, validationError := range e {
		schemaErrors[i] = &schemav1.ValidationError{
			Path:    validationError.Path,
			Message: validationError.Message,
			Source:  validationError.Source,
		}
	}

	return schemaErrors
}
