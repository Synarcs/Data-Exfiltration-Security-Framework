package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
)

type unixSockPath string

const (
	LocalCliUnixSockPath = "/run/clid.sock"
)

// remote config from the centralized server broker
type NodeDaemonCli struct {
	Unixsock       unixSockPath
	UnixSocketConn net.Listener
}

// used for ipv on local node via  unxi domain socket AF_UNIX
func GenerateRemoteCliSocketServer() *NodeDaemonCli {
	return &NodeDaemonCli{
		Unixsock: unixSockPath(LocalCliUnixSockPath),
	}
}

func configureStreamLimits(w http.ResponseWriter, r *http.Request) {
	jsonString, err := json.Marshal(events.MarshallMapStruct())
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		fmt.Fprintln(w, "Error in return the configured limits")
	}
	w.Write(jsonString)
}

func (nc *NodeDaemonCli) ConfigureUnixSocket(globalNodeDErrorChannel chan bool) {

	listener, err := net.Listen("unix", string(nc.Unixsock))
	nc.UnixSocketConn = listener

	if err != nil {
		log.Println("Error opening a local unix socket connection ... ")
		globalNodeDErrorChannel <- true
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/limits", configureStreamLimits)

	server := http.Server{
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(
				context.Background(), "BootTime", time.Now().GoString(),
			)
		},
	}

	server.Serve(listener)

}

func (nc *NodeDaemonCli) CleanRemoteSock() error {
	_, err := os.Stat(LocalCliUnixSockPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err := nc.UnixSocketConn.Close(); err != nil {
		return err
	}

	return nil
}
