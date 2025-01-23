package sidecar

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
)

type MutationWebHook struct {
	Port int
	Addr string
}

// webhook endpoint to process the mutation with adding sidecar for ebpf exfiltration security over DNS
func podSidecarMutateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	mutateMessage := struct {
		MutateMessage string `json:"mutateMessage"`
	}{
		MutateMessage: "The Pod has been mutated with the sidecar for exfiltration security with injected eBPF code for DNS exfiltration security in Kernel",
	}
	json.NewEncoder(w).Encode(mutateMessage)
}

func NewMutationWebHook(port int, addr string) *MutationWebHook {
	return &MutationWebHook{
		Port: port,
		Addr: addr,
	}
}

func (m *MutationWebHook) InitMutationServer(opts ...interface{}) {
	ctx := context.Background()

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", podSidecarMutateHandler)

	server := http.Server{
		Addr:    fmt.Sprintf(":%d", m.Port),
		Handler: mux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	log.Println("Starting the Mutation Webhook Server on port ", m.Port)
	log.Panicln(server.ListenAndServe())
}
