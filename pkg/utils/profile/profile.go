package profile

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
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
		utils.Log(fmt.Sprintf("Starting pprof server on port %d", PPROF_PORT))
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
			if utils.DEBUG {
				utils.Log(fmt.Sprintf("Shutting down pprof server on port %d", PPROF_PORT))
			}
			server.Shutdown(ctx)
		case <-graceFulClose:
			utils.Log("Profile server shutdown gracefully")
			return nil
		case err := <-errorClose:
			return err
		}
	}
}
