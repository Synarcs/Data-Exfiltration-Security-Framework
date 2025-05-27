/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
*/

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/tc"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

type unixSockPath string

const (
	LocalCliUnixSockPath = "/run/dnsobelisk/clid.sock"
)

// remote config from the centralized server broker
type NodeDaemonCli struct {
	Unixsock  unixSockPath
	CloseChan chan bool
	ErorCHan  chan error
}

// used for ipv on local node via  unxi domain socket AF_UNIX
func NewRemoteCliSocketServer() *NodeDaemonCli {
	return &NodeDaemonCli{
		Unixsock:  unixSockPath(LocalCliUnixSockPath),
		CloseChan: make(chan bool), // signal to close the cli server when node agent gracefully shutdowns
		ErorCHan:  make(chan error),
	}
}

func configureStreamLimits(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		return
	}
	jsonString, err := json.Marshal(events.MarshallMapStruct())
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		fmt.Fprintln(w, "Error in return the configured limits")
	}
	w.Write(jsonString)
}

func blacklistIngressDomains(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		return
	}
	info := struct {
		Domains []string
	}{
		Domains: utils.GetBlaclistedDomainsIngressCache(),
	}

	w.Header().Add("Content-Type", "application/json")

	payload, err := json.Marshal(info)
	if err != nil {
		log.Println("Error in marshalling and rerun current state of blacklisted domains for ingress LRU cache")
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(payload); err != nil {
		log.Println("Error writeing the marhalled json")
	}
}

func blacklistEgressDomains(w http.ResponseWriter, r *http.Request) {
	if err := r.Context().Err(); err != nil {
		return
	}
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
	if err := r.Context().Err(); err != nil {
		return
	}
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
			errResponse("Please provide a SLD and not TLD or an FQDN with multiple labels ...")
			return
		}

		if err := utils.DeleteDomainBlackListInEgressCache(sld, ""); err != nil {
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

/*
Combines all the malicious processes prevented by the kernel and user space exfiltrating data
*/
func GetAllPreventedExfiltratedProcessids() (map[uint32]int, []string) {
	combinProc := map[uint32]int{}

	var malProces []string
	defaultPort := model.GetCurrentLoggedExfiltratedProcessids()
	for malProc, ct := range defaultPort {
		if val, fd := combinProc[malProc]; !fd {
			combinProc[malProc] = ct
		} else {
			combinProc[malProc] = val + ct
		}
	}

	tunnelPortMap := tc.GetCurrentLoggedExfiltratedProcessids()

	for tunnelProc, ct := range tunnelPortMap {
		if val, fd := combinProc[tunnelProc]; !fd {
			combinProc[tunnelProc] = ct
		} else {
			combinProc[tunnelProc] = val + ct
		}
	}

	for process := range combinProc {
		malProces = append(malProces, fmt.Sprintf("%d", process))
	}
	return combinProc, malProces
}

func GetMaliciousDetectedProcessCtOnNode(w http.ResponseWriter, r *http.Request) {
	currProcCount, procs := GetAllPreventedExfiltratedProcessids()
	sendResp := func(msg string, procs []string) interface{} {
		return struct {
			MaliciousPreventedProcessCount string
			Procs                          []string
		}{
			MaliciousPreventedProcessCount: msg,
			Procs:                          procs,
		}
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	if len(currProcCount) == 0 {
		json.NewEncoder(w).Encode(
			struct {
				Msg string
			}{
				fmt.Sprintf("No malicious process Detected yet by the node-agent process %d", os.Getpid()),
			},
		)
		return
	}
	slices.Sort(procs)
	json.NewEncoder(w).Encode(
		sendResp(fmt.Sprintf("%d", len(currProcCount)), procs),
	)
}

func (nc *NodeDaemonCli) NewNodeAgentUnixCLISocket() {
	listener, err := net.Listen("unix", string(nc.Unixsock))

	if err != nil {
		log.Println("Error opening a local unix socket connection ... ")
		nc.ErorCHan <- err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/limits", configureStreamLimits)
	mux.HandleFunc("/blacklist/ingress", blacklistIngressDomains)
	mux.HandleFunc("/blacklist/egress", blacklistEgressDomains)
	mux.HandleFunc("/whitelist", UnblockDomain)
	mux.HandleFunc("/malProcessCt", GetMaliciousDetectedProcessCtOnNode)

	server := http.Server{
		Handler: mux,
		BaseContext: func(l net.Listener) context.Context {
			return context.WithValue(
				context.Background(), "BootTime", time.Now().String(),
			)
		},
	}

	defer func() {
		utils.Log("Shutting down Node Agent CLI socket...")
		// the cli sock dont need to be graceful rather abrubt close for all the sock fd to be released and upstream connection to force (since this is over unix socket)
		listener.Close()
		server.Close()
		if _, err := os.Stat(string(nc.Unixsock)); err == nil {
			if err := os.Remove(string(nc.Unixsock)); err != nil {
				utils.Log("Error removing mounted CLI socket:", err)
			}
		}
	}()

	go func() {
		// http l7 overlay over the unix socket
		// TODO: all the l7 should be converted to grpc overlay same way most of cli socket for almost all CNI's
		if err := server.Serve(listener); err != nil {
			nc.ErorCHan <- err
		}
	}()

	for {
		select {
		case err := <-nc.ErorCHan:
			utils.Log("error creating L7 http overlay over unix socket", err.Error())
			return
		case <-nc.CloseChan:
			utils.Log("received to close linux unix mount sock cli channel")
			return
		}
	}
}
