module github.com/inventedsarawak/hyperion/apps/siphon

go 1.26.3

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/onsi/ginkgo/v2 v2.31.0
	github.com/onsi/gomega v1.42.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/pierrec/lz4/v4 v4.1.26 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/twmb/franz-go v1.21.7 // indirect
	github.com/twmb/franz-go/pkg/kadm v1.18.0 // indirect
	github.com/twmb/franz-go/pkg/kmsg v1.13.1 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20260402051712-545e8a4df936 // indirect
	github.com/inventedsarawak/hyperion/packages/common v0.0.0-00010101000000-000000000000
	github.com/inventedsarawak/hyperion/packages/contracts v0.0.0-00010101000000-000000000000
	go.yaml.in/yaml/v3 v3.0.5
	golang.org/x/mod v0.35.0
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/time v0.14.0
	golang.org/x/tools v0.44.0 // indirect
)

replace github.com/inventedsarawak/hyperion/packages/contracts => ../../packages/contracts

replace github.com/inventedsarawak/hyperion/packages/common => ../../packages/common
