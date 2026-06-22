package validate

import (
	"encoding/base64"
	"regexp"
	"unicode"

	"github.com/go-playground/validator/v10"
)

// passwordCharset whitelists the characters permitted in a password: ASCII
// letters and digits plus a fixed set of punctuation/symbols.
var passwordCharset = regexp.MustCompile(`^[0-9a-zA-Z~!@#$%^&*()\-+={}\[\]|\\:;"'<>,.?/_]+$`)

// PasswordPolicy describes the requirements enforced by VerifyPasswordRequirements.
//
// A password is considered valid when, after optional base64 decoding, it:
//   - has a length within [MinLength, MaxLength] (inclusive),
//   - contains at least one uppercase letter, one lowercase letter, one digit,
//     and one special character (punctuation, symbol, or space), and
//   - consists solely of characters in the permitted whitelist.
type PasswordPolicy struct {
	// MinLength is the minimum decoded password length, in bytes.
	MinLength int
	// MaxLength is the maximum decoded password length, in bytes.
	MaxLength int
	// Base64 indicates whether the incoming field value is expected to be a
	// standard-encoding base64 string that must be decoded before the policy is
	// applied. When false, the field value is treated as the raw password.
	//
	// This replaces the original implementation's unconditional base64
	// round-trip, which silently rejected any non-base64 input. Set Base64=true
	// only if your transport actually base64-encodes the secret.
	Base64 bool
}

// VerifyPasswordRequirements implements the "password" rule. The policy applied
// is DefaultPassword; the tag takes no parameter (e.g. `validate:"password"`).
//
// When the policy's Base64 flag is set, the field value is first base64-decoded
// using standard encoding; a decode error fails validation rather than being
// ignored. The decoded (or raw) value is then checked against the policy's
// length bounds, character-class requirements, and character whitelist.
func VerifyPasswordRequirements(fl validator.FieldLevel) bool {
	return checkPassword(fl.Field().String(), DefaultPassword)
}

// checkPassword applies policy to s and reports whether s satisfies it. It is
// separated from the validator.FieldLevel entry point to keep the policy logic
// testable in isolation.
func checkPassword(s string, policy PasswordPolicy) bool {
	if policy.Base64 {
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			// Input was declared base64 but did not decode: reject explicitly.
			return false
		}
		s = string(decoded)
	}

	if len(s) < policy.MinLength || len(s) > policy.MaxLength {
		return false
	}

	var upper, lower, number, special bool
	for _, c := range s {
		switch {
		case unicode.IsNumber(c):
			number = true
		case unicode.IsLetter(c) && unicode.IsUpper(c):
			upper = true
		case unicode.IsLetter(c) && unicode.IsLower(c):
			lower = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c) || c == ' ':
			special = true
		}
	}
	if !(upper && lower && number && special) {
		return false
	}

	return passwordCharset.MatchString(s)
}
