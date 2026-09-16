package grpc

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// describe turns a gRPC failure into a sentence for the person using deck:
// cortex's own message for anything it rejected (it writes those for
// people), and a hint when it could not be reached at all. The status code
// and the "rpc error:" framing are for machines.
func describe(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return errors.New("can't reach cortex — is it running? (task status)")
	case codes.DeadlineExceeded:
		return errors.New("cortex took too long to answer; try again")
	default:
		return errors.New(st.Message())
	}
}
