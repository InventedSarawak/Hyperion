module github.com/inventedsarawak/hyperion/tests/load

go 1.26.3

require (
	github.com/inventedsarawak/hyperion/packages/common v0.0.0-00010101000000-000000000000
	github.com/inventedsarawak/hyperion/packages/contracts v0.0.0-00010101000000-000000000000
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/twmb/franz-go v1.21.7 // indirect
	github.com/twmb/franz-go/pkg/kadm v1.18.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.13.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
)

replace github.com/inventedsarawak/hyperion/packages/common => ../../packages/common

replace github.com/inventedsarawak/hyperion/packages/contracts => ../../packages/contracts
