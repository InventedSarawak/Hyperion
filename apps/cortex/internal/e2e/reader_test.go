package e2e_test

import (
	"io"
	"strings"
)

// stringReader is the event stream cortex reads, one protojson line per event.
func stringReader(s string) io.Reader { return strings.NewReader(s) }
