package kafka_test

import (
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

var _ = Describe("codec", func() {
	It("round-trips a message through the wire encoding", func() {
		in := wrapperspb.String("CVE-2021-44228")

		b, err := kafka.Encode(in)
		Expect(err).NotTo(HaveOccurred())

		var out wrapperspb.StringValue
		Expect(kafka.Decode(b, &out)).To(Succeed())
		Expect(out.GetValue()).To(Equal("CVE-2021-44228"))
	})

	It("names a message by its protobuf full name, not its Go type", func() {
		Expect(kafka.MessageName(wrapperspb.String("x"))).To(Equal("google.protobuf.StringValue"))
	})
})

var _ = Describe("Message.Into", func() {
	It("decodes a record carrying the expected type", func() {
		b, err := kafka.Encode(wrapperspb.String("hello"))
		Expect(err).NotTo(HaveOccurred())

		msg := kafka.Message{Value: b, EventType: "google.protobuf.StringValue"}

		var out wrapperspb.StringValue
		Expect(msg.Into(&out)).To(Succeed())
		Expect(out.GetValue()).To(Equal("hello"))
	})

	It("decodes a record with no event-type header, since the header is an assertion and not evidence", func() {
		b, err := kafka.Encode(wrapperspb.String("hello"))
		Expect(err).NotTo(HaveOccurred())

		var out wrapperspb.StringValue
		Expect(kafka.Message{Value: b}.Into(&out)).To(Succeed())
		Expect(out.GetValue()).To(Equal("hello"))
	})

	It("refuses a record that announces a different type, and calls it unprocessable", func() {
		b, err := kafka.Encode(timestamppb.Now())
		Expect(err).NotTo(HaveOccurred())

		msg := kafka.Message{Topic: "t", Value: b, EventType: "google.protobuf.Timestamp"}

		var out wrapperspb.StringValue
		err = msg.Into(&out)
		Expect(err).To(HaveOccurred())
		// Unprocessable, not retryable: trying it again cannot change the answer.
		Expect(errors.Is(err, kafka.ErrUnprocessable)).To(BeTrue())
	})

	It("reports a value that is not valid protobuf as unprocessable", func() {
		// A length-delimited field that claims more bytes than it has.
		msg := kafka.Message{Value: []byte{0x0a, 0xff}}

		var out wrapperspb.StringValue
		Expect(errors.Is(msg.Into(&out), kafka.ErrUnprocessable)).To(BeTrue())
	})
})
