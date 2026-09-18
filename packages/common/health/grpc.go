package health

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc"
	grpchealth "google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

// ServeGRPC registers the standard gRPC health service and keeps its status up
// to date from the checker.
//
// Standard on purpose: grpc_health_probe, Kubernetes' native gRPC probes and
// grpcurl all speak grpc.health.v1, so nothing has to learn a bespoke endpoint.
//
// The status is polled on a ticker rather than computed per request. A probe
// arrives every few seconds from every prober watching, and asking Postgres on
// each of them would make the health check its own load.
func ServeGRPC(ctx context.Context, server *grpc.Server, checker *Checker, every time.Duration, logger *slog.Logger) {
	if every <= 0 {
		every = 10 * time.Second
	}
	srv := grpchealth.NewServer()
	healthv1.RegisterHealthServer(server, srv)

	// Start as NOT_SERVING: nothing has been asked yet, and claiming to serve
	// before the first check is exactly the lie this exists to prevent.
	srv.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)

	go func() {
		ticker := time.NewTicker(every)
		defer ticker.Stop()

		var (
			lastStatus  healthv1.HealthCheckResponse_ServingStatus = -1
			lastFailing                                            = "\x00" // never equal to a real answer
			first                                                  = true
		)
		for {
			report := checker.Run(ctx)
			status := healthv1.HealthCheckResponse_NOT_SERVING
			if report.Healthy {
				status = healthv1.HealthCheckResponse_SERVING
			}
			if status != lastStatus {
				srv.SetServingStatus("", status)
				lastStatus = status
			}

			// Logged on a change of *what is failing*, not of serving status.
			// An optional dependency going down leaves the status alone by
			// design, and reporting only on status changes would make the one
			// kind of trouble this tolerates the one kind nobody hears about.
			if failing := strings.Join(report.Failing(), ","); failing != lastFailing {
				switch {
				case !report.Healthy:
					logger.Error("health: not serving", "failing", report.Failing())
				case report.Degraded():
					logger.Warn("health: serving, degraded", "failing", report.Failing())
				case !first:
					logger.Info("health: serving, all dependencies recovered")
				default:
					logger.Info("health: serving")
				}
				lastFailing = failing
			}
			first = false

			select {
			case <-ctx.Done():
				// Say so before going: a graceful stop that still reports
				// SERVING keeps traffic arriving while it drains.
				srv.Shutdown()
				return
			case <-ticker.C:
			}
		}
	}()
}
