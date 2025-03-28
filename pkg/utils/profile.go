package utils

import (
	 _ "net/http/pprof"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
)

// runs system profile for the eBPF node agent in user space
// added this primarily to have flame-graph system cpu profiling for monitoring kernel syscalls in addition to bpftop and perf for user space
const (
	PPROF_PORT = 6262
)

func InitProfileServer(ctx context.Context) error {
	var graceFulClose chan bool
	var errorClose chan error

	server := http.Server{
		Addr: fmt.Sprintf(":%d", PPROF_PORT),
		BaseContext: func(net.Listener) context.Context {
			return ctx
		},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	go func() {
		log.Printf("Starting pprof server on port %d", PPROF_PORT)
		if err := server.ListenAndServe(); err != nil {
			if errors.Is(err, http.ErrServerClosed) {
				graceFulClose <- true
				return
			}
			errorClose <- err
			return
		}
	}()
	for {
		select {
		case <-ctx.Done():
			if DEBUG {
				log.Printf("Shutting down pprof server on port %d", PPROF_PORT)
			}
			server.Shutdown(ctx)
		case <-graceFulClose:
			log.Println("Profile server shutdown gracefully")
			return nil
		case err := <-errorClose:
			return err
		}
	}
}
