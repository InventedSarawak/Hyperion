package kafka_test

import (
	"context"
	"errors"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/inventedsarawak/hyperion/packages/common/kafka"
)

var _ = Describe("ParseBrokers", func() {
	It("splits a comma-separated list and drops blanks", func() {
		Expect(kafka.ParseBrokers("a:9092, b:9092 ,, c:9092 ")).
			To(Equal([]string{"a:9092", "b:9092", "c:9092"}))
	})

	It("returns nothing for an empty setting, so the caller fails loudly", func() {
		Expect(kafka.ParseBrokers("   ")).To(BeEmpty())
	})
})

var _ = Describe("construction", func() {
	It("refuses a producer with no brokers rather than retrying nowhere forever", func() {
		_, err := kafka.NewProducer(kafka.Config{}, kafka.TopicSignals)
		Expect(errors.Is(err, kafka.ErrNoBrokers)).To(BeTrue())
	})

	It("refuses a producer with no topic", func() {
		_, err := kafka.NewProducer(kafka.Config{Brokers: []string{"localhost:9092"}}, "")
		Expect(err).To(MatchError(ContainSubstring("needs a topic")))
	})

	It("refuses a consumer with no group, since offsets have nowhere to live", func() {
		_, err := kafka.NewConsumer(kafka.Config{Brokers: []string{"localhost:9092"}}, kafka.TopicSignals, "")
		Expect(err).To(MatchError(ContainSubstring("needs a topic and a group")))
	})

	It("refuses to ensure a topic without brokers", func() {
		Expect(errors.Is(
			kafka.EnsureTopic(context.Background(), kafka.Config{}, "t", 6),
			kafka.ErrNoBrokers,
		)).To(BeTrue())
	})
})
