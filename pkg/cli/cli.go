package cli

import (
	"errors"
	"log"
	"net"
	"os"
)

type unixSockPath string

const (
	LocalCliUnixSockPath = "/run/clid.sock"
)

// remote config from the centralized server broker
type NodeDaemonCli struct {
	Unixsock unixSockPath
}

// used for ipv on local node via  unxi domain socket AF_UNIX
func GenerateRemoteCliSocketServer() *NodeDaemonCli {
	return &NodeDaemonCli{
		Unixsock: "",
	}
}

func (nc *NodeDaemonCli) ConfigureUnixSocket(globalNodeDErrorChannel chan bool) {

	listener, err := net.Listen("unix", string(nc.Unixsock))
	if err != nil {
		log.Println("Error opening a local unix socket connection ... ")
		globalNodeDErrorChannel <- true
		return
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Println(err.Error())
			globalNodeDErrorChannel <- true
			return
		}
		go func(conn net.Conn) {

			defer conn.Close()
		}(conn)
	}
}

func (nc *NodeDaemonCli) CleanRemoteSock() error {
	_, err := os.Stat(LocalCliUnixSockPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err := os.Remove(LocalCliUnixSockPath); err != nil {
		log.Println("Error removing the local unix socket ... , has open fd and sokc linter attached to other process in kernel")
		return err
	}

	return nil
}
