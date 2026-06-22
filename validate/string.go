package validate

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

// uuidRegexp matches a canonical 8-4-4-4-12 hexadecimal UUID string. Matching is
// performed case-insensitively by lower-casing the input before testing.
var uuidRegexp = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// VerifyRegexp implements the "regexp" rule: the field's string value must match
// the regular expression supplied as the tag parameter, e.g.
// `validate:"regexp=^[a-z]+$"`.
//
// An empty or syntactically invalid pattern causes validation to fail rather
// than panic. Note that go-playground/validator strips the tag parameter at the
// first comma, so patterns containing a comma cannot be expressed this way.
func VerifyRegexp(fl validator.FieldLevel) bool {
	pattern := fl.Param()
	if pattern == "" {
		return false
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return re.MatchString(fl.Field().String())
}

// VerifyMaxLength implements the "maxlength" rule: the field's string length, in
// bytes, must not exceed the integer supplied as the tag parameter, e.g.
// `validate:"maxlength=255"`. A missing or non-numeric parameter fails
// validation.
func VerifyMaxLength(fl validator.FieldLevel) bool {
	maxLen, err := strconv.Atoi(fl.Param())
	if err != nil {
		return false
	}
	return len(fl.Field().String()) <= maxLen
}

// VerifyTextContentMax implements the "textmax" rule: a more lenient variant of
// VerifyMaxLength intended for large free-text fields. The field's byte length
// must not exceed the integer tag parameter; when no parameter is supplied the
// package-level DefaultTextContentMax is used.
func VerifyTextContentMax(fl validator.FieldLevel) bool {
	maxBytes := DefaultTextContentMax
	if param := fl.Param(); param != "" {
		n, err := strconv.Atoi(param)
		if err != nil {
			return false
		}
		maxBytes = n
	}
	return len(fl.Field().String()) <= maxBytes
}

// VerifyUUID implements the "uuid_v4" rule: the field must be a canonical
// 8-4-4-4-12 hexadecimal UUID string. Matching is case-insensitive.
func VerifyUUID(fl validator.FieldLevel) bool {
	return uuidRegexp.MatchString(strings.ToLower(fl.Field().String()))
}
