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
	"sync"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
)

type MutationWebHook struct {
	Port int
	Addr string
}

// webhook endpoint to process the mutation with adding sidecar for ebpf exfiltration security over DNS
func podSidecarMutateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	sendResponse := func(msg string) interface{} {
		injecteBPfSockFilterResp := struct {
			MutateMessage string `json:"mutateMessage"`
		}{
			MutateMessage: msg,
		}
		return injecteBPfSockFilterResp
	}
	if err := InjectKernelSocketFilters(); err != nil {
		resp := sendResponse(
			"Error injecting the eBPF sock filter via the sidecar for the pod networking err :" + err.Error(),
		)
		json.NewEncoder(w).Encode(resp)
	} else {
		resp :=
			sendResponse(
				"The Pod has been mutated with the sidecar for exfiltration security with injected eBPF code for DNS exfiltration security in Kernel",
			)
		json.NewEncoder(w).Encode(resp)
	}

}

func NewMutationWebHook(port int, addr string) *MutationWebHook {
	return &MutationWebHook{
		Port: port,
		Addr: addr,
	}
}

func (m *MutationWebHook) InitMutationServer(opts ...interface{}) {
	ctx := context.Background()

	var mutationServerwg sync.WaitGroup
	flag.Usage = func() {
		flag.PrintDefaults()
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/mutate", podSidecarMutateHandler)

	mutationServerwg.Add(1)
	go func() {
		defer mutationServerwg.Done()
		go events.StartPrometheusMetricExporterServer(nil)
	}()

	mutationServerwg.Add(1)
	go func() {
		defer mutationServerwg.Done()
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

		if err := server.ListenAndServe(); err != nil {
			log.Println("Error starting the mutation server")
			panic(err.Error())
		}
	}()

	mutationServerwg.Wait()
}
