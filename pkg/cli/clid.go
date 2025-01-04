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
	"strings"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
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

func blacklistIngressDomains(w http.ResponseWriter, r *http.Request) {
	info := struct {
		Domains []string
	}{
		Domains: utils.GetBlaclistedDomainsIngressCache(),
	}

	w.Header().Add("Content-Type", "application/json")

	payload, err := json.Marshal(info)
	if err != nil {
		log.Println("Error in marshalling and rerun current state of blacklisted domains for ingress LRU cache")
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		log.Println("Error writeing the marhalled json")
	}
}

func blacklistEgressDomains(w http.ResponseWriter, r *http.Request) {
	info := struct {
		Domains []string
	}{
		Domains: utils.GetBlaclistedDomainsEgressCache(),
	}

	w.Header().Add("Content-Type", "application/json")

	payload, err := json.Marshal(info)
	if err != nil {
		log.Println("Error in marshalling and rerun current state of blacklisted domains for ingress LRU cache")
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		log.Println("Error writeing the marhalled json")
	}
}

func UnblockDomain(w http.ResponseWriter, r *http.Request) {
	sld := r.URL.Query().Get("domain")

	log.Println("The domain to be unblocked is .....", sld)

	errResponse := func(errMessage string) {
		err := struct {
			Error string
		}{
			Error: errMessage,
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		if err := json.NewEncoder(w).Encode(err); err != nil {
			log.Println("Error the required JSON cannot be encoded ...")
		}
	}

	successResponse := func(msg string) {
		message := struct {
			Msg string
		}{
			Msg: msg,
		}

		w.Header().Add("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)

		if err := json.NewEncoder(w).Encode(message); err != nil {
			log.Println("Error the required JSON cannot be encoded ...")
		}
	}
	if len(sld) >= 0 && len(sld) <= (1<<8)-1 {
		// unblock the domain both over ingress and egress routes
		if strings.Count(strings.TrimSpace(sld), ".") != 1 {
			log.Println()
			errResponse("Please provide a SLD and not TLD or an FQDN with multiple labels ...")
			return
		}

		if err := utils.DeleteDomainBlackListInCache(sld, ""); err != nil {
			errResponse(err.Error())
			return
		}
		// ignore ingress anyways it will be synced with lock and concurrency control from egress cache
		utils.IngDeleteDomainBlackListInCache(sld)
		successResponse("Success")
		return
	}

	errResponse("Error this is not an valid domain to be removed from blaclisted cahce, ensure it adheres to RFC 1035..")
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
	mux.HandleFunc("/blacklist/ingress", blacklistIngressDomains)
	mux.HandleFunc("/blacklist/egress", blacklistEgressDomains)
	mux.HandleFunc("/whitelist", UnblockDomain)

	server := http.Server{
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(
				context.Background(), "BootTime", time.Now().String(),
			)
		},
	}

	server.Serve(listener)

}

func (nc *NodeDaemonCli) CleanRemoteSock() error {
	if nc.UnixSocketConn == nil {
		return nil
	}
	_, err := os.Stat(LocalCliUnixSockPath)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}

	if err := nc.UnixSocketConn.Close(); err != nil {
		return err
	}

	return nil
}
