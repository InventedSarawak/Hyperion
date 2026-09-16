package grpc

import (
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDescribeWordsFailuresForPeople(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"cortex's own words", status.Error(codes.NotFound, "no finding is known by CVE-1"), "no finding is known by CVE-1"},
		{"a rejected request", status.Error(codes.InvalidArgument, "enter a finding id"), "enter a finding id"},
		{"cortex down", status.Error(codes.Unavailable, "connection refused"), "can't reach cortex"},
		{"cortex slow", status.Error(codes.DeadlineExceeded, "deadline exceeded"), "took too long"},
		{"not a gRPC error", errors.New("plain"), "plain"},
	}
	for _, c := range cases {
		got := describe(c.err).Error()
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: got %q, want it to contain %q", c.name, got, c.want)
		}
		if strings.Contains(got, "rpc error") || strings.Contains(got, "code =") {
			t.Errorf("%s: %q still carries the gRPC framing", c.name, got)
		}
	}
}
