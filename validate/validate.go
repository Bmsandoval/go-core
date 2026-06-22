// Package validate provides a set of reusable custom validation rules for
// github.com/go-playground/validator/v10.
//
// The rules in this package are deliberately framework-agnostic and domain-free:
// they validate generic shapes (regular expressions, lengths, UUIDs, decimal
// bounds, password strength) rather than any application's business concepts.
//
// # Usage
//
// Unlike many validator helpers, this package exposes no package-level singleton
// *validator.Validate. Instead, the caller constructs (and owns) the validator
// instance and passes it to Register, which installs every rule:
//
//	v := validator.New(validator.WithRequiredStructEnabled())
//	if err := validate.Register(v); err != nil {
//		log.Fatal(err)
//	}
//
// After registration the following tags become available:
//
//	regexp           - field must match the regular expression given as the tag parameter.
//	maxlength        - string length (in bytes) must not exceed the tag parameter.
//	textmax          - alias of maxlength with a configurable default (see DefaultTextContentMax).
//	uuid_v4          - field must be a canonical 8-4-4-4-12 hex UUID string.
//	decimalmax       - numeric field must be in the inclusive range [0, max]; the
//	                   max comes from the tag parameter, or DefaultDecimalMax.
//	decimalprecision - numeric field must have at most the given number of decimal
//	                   places (tag parameter, or DefaultDecimalPlaces).
//	password         - string must satisfy the configured password requirements.
//
// # Configurable defaults
//
// Several rules accept their bounds via the tag parameter but also fall back to
// package-level variables so that an application can set sane defaults once and
// then use the bare tag (e.g. `validate:"decimalmax"`). These variables are read
// at validation time, so changing them affects subsequent validations. They are
// not safe to mutate concurrently with validation; set them during program
// initialization.
package validate

import "github.com/go-playground/validator/v10"

// Configurable package-level defaults. These are consulted only when a rule's
// tag parameter is empty, allowing callers to choose between a global default
// and a per-field override.
var (
	// DefaultTextContentMax is the maximum byte length used by the "textmax"
	// rule when no tag parameter is supplied. Defaults to 100 KiB.
	DefaultTextContentMax = 100 * 1024

	// DefaultDecimalMax is the inclusive upper bound used by the "decimalmax"
	// rule when no tag parameter is supplied. The default mirrors the maximum
	// value representable by a SQL DECIMAL(8,2) column.
	DefaultDecimalMax = 999999.99

	// DefaultDecimalPlaces is the maximum number of fractional digits allowed by
	// the "decimalprecision" rule when no tag parameter is supplied.
	DefaultDecimalPlaces = 2

	// DefaultPassword holds the password policy used by the "password" rule when
	// no tag parameter is supplied. Its fields may be tuned at program startup.
	DefaultPassword = PasswordPolicy{
		MinLength: 12,
		MaxLength: 36,
		Base64:    false,
	}
)

// rule pairs a validator tag with its registration function.
type rule struct {
	tag string
	fn  validator.Func
}

// rules is the canonical list of custom rules installed by Register.
func rules() []rule {
	return []rule{
		{"regexp", VerifyRegexp},
		{"maxlength", VerifyMaxLength},
		{"textmax", VerifyTextContentMax},
		{"uuid_v4", VerifyUUID},
		{"decimalmax", VerifyDecimalMax},
		{"decimalprecision", VerifyDecimalPrecision},
		{"password", VerifyPasswordRequirements},
	}
}

// Register installs every custom rule in this package onto the supplied
// *validator.Validate. It returns the first registration error encountered, if
// any. The caller retains ownership of v and may register additional rules of
// its own before or after calling Register.
//
// Register is idempotent: registering the same tag twice simply overwrites the
// previous function with an identical one.
func Register(v *validator.Validate) error {
	if v == nil {
		return errNilValidator
	}
	for _, r := range rules() {
		if err := v.RegisterValidation(r.tag, r.fn); err != nil {
			return err
		}
	}
	return nil
}
