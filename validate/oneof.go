package validate

import (
	"strings"

	"github.com/go-playground/validator/v10"
)

// OneOfFunc builds a validator.Func that accepts a string field only if its
// value is one of the caller-supplied allowed values. This is the generic,
// domain-free replacement for ezsplit's hardcoded provider validator
// (["plaid", "venmo"]): the allowed set is supplied by the caller rather than
// baked into the package.
//
// The returned function trims surrounding whitespace and compares
// case-insensitively, matching the lenient behavior of the original.
//
// Because the allowed set is captured in a closure rather than passed via the
// tag parameter, register it under your own tag name, for example:
//
//	v.RegisterValidation("provider", validate.OneOfFunc("plaid", "venmo"))
//
// and then use `validate:"provider"` on the relevant field.
func OneOfFunc(allowed ...string) validator.Func {
	// Normalize the allowed set once at construction time.
	set := make(map[string]struct{}, len(allowed))
	for _, a := range allowed {
		set[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	return func(fl validator.FieldLevel) bool {
		s := strings.ToLower(strings.TrimSpace(fl.Field().String()))
		_, ok := set[s]
		return ok
	}
}
