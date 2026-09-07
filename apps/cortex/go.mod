module github.com/inventedsarawak/hyperion/apps/cortex

go 1.26.3

require (
	github.com/jackc/pgx/v5 v5.10.0
	github.com/onsi/ginkgo/v2 v2.31.0
	github.com/onsi/gomega v1.42.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
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
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/mod v0.35.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
)

replace github.com/inventedsarawak/hyperion/packages/contracts => ../../packages/contracts

replace github.com/inventedsarawak/hyperion/packages/common => ../../packages/common
