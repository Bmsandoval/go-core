package validate

import "errors"

// errNilValidator is returned by Register when given a nil *validator.Validate.
var errNilValidator = errors.New("validate: nil *validator.Validate passed to Register")
