package kafka

import (
	"fmt"

	"github.com/twmb/franz-go/pkg/kgo"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Record header keys. Kafka headers are the envelope around an opaque value:
// they let a consumer decide whether it can read a record before it tries.
const (
	// HeaderEventType carries the protobuf full message name, e.g.
	// "hyperion.events.v1.SignalDiscovered". A consumer reading a topic that
	// later carries more than one message type needs this to dispatch.
	HeaderEventType = "event-type"

	// HeaderContentType says how the value is encoded. Binary protobuf today;
	// naming it means a future protojson or Avro record is detectable rather
	// than a decode failure.
	HeaderContentType = "content-type"

	// ContentTypeProtobuf is the only encoding Hyperion produces.
	ContentTypeProtobuf = "application/x-protobuf"
)

// Encode marshals a contract message to the bytes that go on the topic.
//
// Binary protobuf, not protojson: it is three to five times smaller, and it is
// the canonical encoding — protojson is a debugging convenience that happens
// to round-trip. Use `task topic:tail` to read a topic in human form.
func Encode(m proto.Message) ([]byte, error) {
	b, err := proto.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("kafka: marshal %s: %w", messageName(m), err)
	}
	return b, nil
}

// Decode unmarshals a record value into m.
func Decode(b []byte, m proto.Message) error {
	if err := proto.Unmarshal(b, m); err != nil {
		return fmt.Errorf("kafka: unmarshal %s: %w", messageName(m), err)
	}
	return nil
}

// messageName is the protobuf full name, used in headers and error text.
func messageName(m proto.Message) string {
	if m == nil {
		return "<nil>"
	}
	return string(m.ProtoReflect().Descriptor().FullName())
}

// MessageName exposes the protobuf full name of a message.
func MessageName(m proto.Message) string { return messageName(m) }

// headersFor builds the envelope for a message.
func headersFor(m proto.Message) []kgo.RecordHeader {
	return []kgo.RecordHeader{
		{Key: HeaderEventType, Value: []byte(messageName(m))},
		{Key: HeaderContentType, Value: []byte(ContentTypeProtobuf)},
	}
}

// Header reads one header off a record, or "" when it is absent.
func Header(rec *kgo.Record, key string) string {
	for _, h := range rec.Headers {
		if h.Key == key {
			return string(h.Value)
		}
	}
	return ""
}

// EventTypeMatches reports whether a record claims to carry the given message
// type. A record with no event-type header is accepted: the header is an
// assertion, and its absence is not evidence of the wrong type.
func EventTypeMatches(rec *kgo.Record, want protoreflect.FullName) bool {
	got := Header(rec, HeaderEventType)
	return got == "" || got == string(want)
}
