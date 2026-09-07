package sourcehttp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// FlexFloat is a float64 that accepts either a JSON number or a JSON string.
//
// Several upstream APIs are inconsistent about this: Red Hat returns CVSS
// scores as strings ("7.8"), Shodan returns versions as numbers (4.0), and
// both use null for "unknown". Decoding straight into float64 fails on the
// string form, so every numeric field from these feeds uses this type.
type FlexFloat float64

// UnmarshalJSON accepts a number, a quoted number, or null.
func (f *FlexFloat) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		*f = 0
		return nil
	}

	// Strip surrounding quotes when the value arrives as a string.
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		if s == "" {
			*f = 0
			return nil
		}
		v, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("flexfloat: %q is not numeric: %w", s, err)
		}
		*f = FlexFloat(v)
		return nil
	}

	var v float64
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*f = FlexFloat(v)
	return nil
}

// Float returns the underlying float64.
func (f FlexFloat) Float() float64 { return float64(f) }
