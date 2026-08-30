// Command server is nexus's entrypoint: the API gateway. It exposes GraphQL
// over HTTP and satisfies queries by calling cortex over gRPC.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/inventedsarawak/hyperion/packages/common/env"

	graphqladapter "github.com/inventedsarawak/hyperion/apps/nexus/internal/adapters/inbound/graphql"
	grpcadapter "github.com/inventedsarawak/hyperion/apps/nexus/internal/adapters/outbound/grpc"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/application/queries"
	"github.com/inventedsarawak/hyperion/apps/nexus/internal/platform/config"
)

func main() {
	// Load .env (if present) before reading any configuration.
	env.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg := config.Load()

	// Compose the hexagon: outbound adapter -> use case -> inbound adapter.
	intelligence, err := grpcadapter.Dial(cfg.CortexAddr)
	if err != nil {
		logger.Error("cortex dial failed", "addr", cfg.CortexAddr, "error", err)
		os.Exit(1)
	}
	defer intelligence.Close()

	search := queries.NewSearchVulnerabilities(intelligence)

	schema, err := graphqladapter.NewSchema(search)
	if err != nil {
		logger.Error("graphql schema build failed", "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()
	mux.Handle("/graphql", graphqladapter.NewHandler(schema))
	mux.Handle("/playground", graphqladapter.NewPlaygroundHandler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		logger.Info("shutting down http server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	logger.Info("nexus listening",
		"addr", cfg.HTTPAddr,
		"cortex", cfg.CortexAddr,
		"graphql", "POST /graphql",
		"playground", "GET /playground",
	)

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("http serve failed", "error", err)
		os.Exit(1)
	}
	logger.Info("nexus stopped")
}
