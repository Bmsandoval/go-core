package validate

import (
	"math"
	"reflect"
	"strconv"

	"github.com/go-playground/validator/v10"
)

// fieldFloat extracts a float64 from a float-kinded field, reporting whether the
// field is actually a float kind.
func fieldFloat(field reflect.Value) (float64, bool) {
	switch field.Kind() {
	case reflect.Float32, reflect.Float64:
		return field.Float(), true
	default:
		return 0, false
	}
}

// VerifyDecimalMax implements the "decimalmax" rule: a float32/float64 field must
// lie within the inclusive range [0, max]. The upper bound is taken from the tag
// parameter (e.g. `validate:"decimalmax=500.00"`); when no parameter is supplied
// the package-level DefaultDecimalMax is used.
//
// The default mirrors a SQL DECIMAL(8,2) column's maximum (999999.99). Negative
// values always fail. Non-float fields fail.
func VerifyDecimalMax(fl validator.FieldLevel) bool {
	value, ok := fieldFloat(fl.Field())
	if !ok {
		return false
	}

	maxValue := DefaultDecimalMax
	if param := fl.Param(); param != "" {
		m, err := strconv.ParseFloat(param, 64)
		if err != nil {
			return false
		}
		maxValue = m
	}

	return value >= 0 && value <= maxValue
}

// VerifyDecimalPrecision implements the "decimalprecision" rule: a float32/float64
// field must have no more than the allowed number of fractional digits. The
// allowance is taken from the tag parameter (e.g. `validate:"decimalprecision=4"`);
// when no parameter is supplied the package-level DefaultDecimalPlaces is used.
//
// Because binary floating point cannot represent most decimal fractions exactly,
// the check scales the value by 10^places and tolerates a small epsilon when
// comparing against the nearest whole number. Non-float fields fail.
func VerifyDecimalPrecision(fl validator.FieldLevel) bool {
	value, ok := fieldFloat(fl.Field())
	if !ok {
		return false
	}

	places := DefaultDecimalPlaces
	if param := fl.Param(); param != "" {
		p, err := strconv.Atoi(param)
		if err != nil || p < 0 {
			return false
		}
		places = p
	}

	scale := math.Pow(10, float64(places))
	scaled := value * scale
	return math.Abs(scaled-math.Round(scaled)) < 0.0001
}
