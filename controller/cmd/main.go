package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Synarcs/DNSObelisk/controller/cni"
)

const (
	CNI_CONTROLLER_SOCK = "/run/controller-cni.sock"
)

type Router struct {
	NetworkPolicy cni.NetworkPolicies
}

func (router *Router) L3PolicyHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		log.Println("cannnot process the request due to context error", err.Error())
		return
	}
}

func (router *Router) L7PolicyHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		log.Println("cannnot process the request due to context error", err.Error())
		return
	}
}

func main() {
	log.Println("Add the required network policies enforced by the eBPF Node Agent to controller for dynamic network policies for remote c2 servers")
	sock, err := net.Listen("unix", CNI_CONTROLLER_SOCK)

	controlSigKillChan := make(chan os.Signal, 1)
	signal.Notify(controlSigKillChan, syscall.SIGINT, syscall.SIGTERM)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	if err != nil {
		log.Printf("Error in starting the controller CNI server %s", err.Error())
	}

	defer sock.Close()

	router := &Router{
		NetworkPolicy: cni.NewCiliunNetworkPolicy(),
	}

	serverMux := http.NewServeMux()
	serverMux.HandleFunc("/cni/cilium/l3", router.L3PolicyHandler)
	serverMux.HandleFunc("/cni/cilium/l7", router.L7PolicyHandler)

	server := &http.Server{
		Handler: serverMux,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(ctx, "BootTime", time.Now().String())
		},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	go func() {
		if err := server.Serve(sock); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		} else {
			log.Println("Controller sock started successfully ", CNI_CONTROLLER_SOCK)
		}
	}()

	defer func() {
		server.Close()
		sock.Close()
		if _, err := os.Stat(CNI_CONTROLLER_SOCK); err == nil {
			if err := os.Remove(CNI_CONTROLLER_SOCK); err != nil {
				log.Println("Error removing mounted CNI socket:", err)
			}
		}
	}()

	for {
		select {
		case <-controlSigKillChan:
			log.Println("the CNI socket would be closed on the controller cleanning all controller sock")
			cancel()
			return
		default:
			time.Sleep(time.Second)
		}
	}
}
