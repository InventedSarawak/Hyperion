// Package telemetry will hold Hyperion's shared OpenTelemetry and logging
// setup: tracer/meter providers, exporters, and the helpers that propagate
// trace context across gRPC and Kafka boundaries.
//
// It is deliberately empty until v6 (see docs/TODO.md). The module exists now
// so every service can depend on the same import path from the start, rather
// than a later rename rippling through every go.mod. This file keeps it a
// valid Go package: a module with no packages at all makes `go vet ./...` and
// editor tooling report an error on an otherwise healthy tree.
package telemetry
