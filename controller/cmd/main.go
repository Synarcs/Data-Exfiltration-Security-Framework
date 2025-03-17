package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Synarcs/DNSObelisk/controller/cni"
	"github.com/Synarcs/DNSObelisk/controller/conf"
	"github.com/Synarcs/DNSObelisk/controller/consumer"
	"github.com/Synarcs/DNSObelisk/controller/k8s"
)

const (
	CNI_CONTROLLER_SOCK = "/tmp/controller-cni.sock"
	Version             = "0.0.1"
)

type Router struct {
	NetworkPolicy cni.NetworkPolicies
}

func (router *Router) version(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		log.Println("cannnot process the request due to context error", err.Error())
		return
	}
	w.WriteHeader(http.StatusAccepted)
	w.Header().Add("Content-Type", "text/plain")
	w.Write([]byte(Version))
}

func LoadConfigFromController() (*conf.GlobalControllerConfig, *consumer.StreamConsumer) {
	if err := consumer.VerifyControllerSockHealthy(); err != nil {
		panic(err.Error())
	}
	globalControllerConfig, streamConsumerConfig := consumer.InitControllerBrokerConfig()
	if globalControllerConfig == nil {
		panic(fmt.Errorf("Cannot boot the cni controller config unless the parent controller is healthy"))
	}
	return globalControllerConfig, streamConsumerConfig
}

func main() {
	log.Println("Add the required network policies enforced by the eBPF Node Agent to controller for dynamic network policies for remote c2 servers")
	sock, err := net.Listen("unix", CNI_CONTROLLER_SOCK)

	controlSigKillChan := make(chan os.Signal, 1)
	errChan := make(chan error)
	signal.Notify(controlSigKillChan, syscall.SIGINT, syscall.SIGTERM)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	if err != nil {
		log.Printf("Error in starting the controller CNI server %s", err.Error())
	}

	// read the controller config from the kafka consumer for infer controller events
	globalControllerConfig, streamConsumer := LoadConfigFromController()

	serverMux := http.NewServeMux()

	server := &http.Server{
		Handler: serverMux,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(ctx, "BootTime", time.Now().String())
		},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}

	k8sClientSet, err := k8s.InitK8sClientSet("")

	if err != nil {
		log.Println("the cni netpool handler for controller cannot load without valid k8ss client set provided")
	} else {

		var cniNetPoolHandler cni.NetworkPolicies
		switch globalControllerConfig.K8sCniConfig.Cni.Name {
		case "cilium":
			cniNetPoolHandler = cni.NewCiliunNetworkPolicy(k8sClientSet)
		default:
			cniNetPoolHandler = cni.NewCiliunNetworkPolicy(k8sClientSet)
		}

		log.Println("the broker config for unix sock server consume events from controller ", streamConsumer.KafkaBrokerConfig.Brokers)

		go func() {
			if err := server.Serve(sock); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Server error: %v", err)
			}
			// the parrent or main go routine will gracefully shutdown the server and underlying unix sock transport server
		}()

		go func() {
			if err := streamConsumer.ConsumeStreamControllerTopic(ctx, cniNetPoolHandler); err != nil {
				errChan <- err
				return
			}
		}()
	}

	defer func() {
		log.Println("Closing the controller unix socket stream Consumer")
		streamConsumer.CloseConsumer()

		log.Println("Closing the Unix Socket Server for the controller")
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
		case err := <-errChan:
			log.Println("Received error  ", err.Error())
			return
		case <-controlSigKillChan:
			log.Println("the CNI socket would be closed on the controller cleanning all controller sock")
			cancel()
			return
		default:
			time.Sleep(time.Second)
		}
	}
}
