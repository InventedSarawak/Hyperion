// Command probe asks a Hyperion service whether it is healthy, for a container
// healthcheck.
//
// The service images are distroless: no shell, no curl, nothing but the binary.
// That is the point of them — every tool in an image is something an attacker
// who gets in can use — but it leaves a healthcheck nothing to run. This is the
// one tool they carry, and it does exactly one thing.
//
//	probe http://127.0.0.1:8080/healthz   # 0 when the endpoint answers 200
//	probe grpc 127.0.0.1:50051            # 0 when grpc.health.v1 says SERVING
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
)

// timeout is shorter than any sensible healthcheck interval, so a hung service
// is reported as unhealthy rather than leaving probes piling up.
const timeout = 3 * time.Second

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var err error
	switch {
	case len(os.Args) == 2 && strings.HasPrefix(os.Args[1], "http"):
		err = probeHTTP(ctx, os.Args[1])
	case len(os.Args) == 3 && os.Args[1] == "grpc":
		err = probeGRPC(ctx, os.Args[2])
	default:
		fmt.Fprintln(os.Stderr, "usage: probe <http-url> | probe grpc <host:port>")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		os.Exit(1)
	}
}

func probeHTTP(ctx context.Context, url string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", url, resp.StatusCode)
	}
	return nil
}

func probeGRPC(ctx context.Context, addr string) error {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return err
	}
	defer conn.Close()
	resp, err := healthv1.NewHealthClient(conn).Check(ctx, &healthv1.HealthCheckRequest{})
	if err != nil {
		return err
	}
	if s := resp.GetStatus(); s != healthv1.HealthCheckResponse_SERVING {
		return fmt.Errorf("%s is %s", addr, s)
	}
	return nil
}
