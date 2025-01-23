package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
)

func getMutationWebHookPort(ctx context.Context) int {
	val, fd := os.LookupEnv("EXFIL_SEC_MUTATION_HOOK_PORT")
	if !fd {
		panic(fmt.Errorf("The mutation webhook for exfiltrate security sidecar cannot start without a port"))
	}
	port, _ := strconv.Atoi(val) // the port will always be a number valid in env for mutation webhook service
	return port
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

var debugHook bool = false

func main() {
	ctx := context.Background()
	var debug bool
	log.Println("The Node Agent Mutation Hook", os.Getpid())
	flag.BoolVar(&debug, "debug", false, "Run the Node Agent in debug mode")
	flag.Usage = func() {
		fmt.Println("Usage: node_agent [options]")
		flag.PrintDefaults()
	}

	flag.Usage = func() {
		flag.PrintDefaults()
	}

	if debug {
		debugHook = true
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", podSidecarMutateHandler)

	port := getMutationWebHookPort(ctx)
	server := http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		BaseContext: func(l net.Listener) context.Context {
			return ctx
		},
	}

	log.Println("Starting the Mutation Webhook Server on port ", port)
	log.Panicln(server.ListenAndServe())
}
