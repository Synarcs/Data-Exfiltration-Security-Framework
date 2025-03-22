/*
Copyright © 2024 Syncarcs
*/
package cmd

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"reflect"
	"time"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/cmd/consts"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
)

func GeteBPFAgentRemoteSockConn() (net.Conn, *http.Client, error) {
	conn, err := net.Dial("unix", consts.LocalCliUnixSockPath)
	if err != nil {
		log.Println("Error connecting to th Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return nil, nil, err
	}

	connRef := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
			MaxIdleConns: 100,
		},
		Timeout: time.Second * 5,
	}

	return conn, connRef, nil
}

func GetCurrentBootedNodeAgentConfigLimits() error {

	_, connRef, err := GeteBPFAgentRemoteSockConn()
	if err != nil {
		return err
	}

	resp, err := connRef.Get(fmt.Sprintf("http://%s/limits", "unix"))
	if err != nil {
		log.Println("Error connecting to the Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return err
	}

	defer resp.Body.Close()
	var limits events.DNSKernelFeatureLimits

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading the response body from the Node Agent")
		return err
	}

	if err := json.Unmarshal(body, &limits); err != nil {
		log.Println(err.Error())
		return err
	}

	log.Println(reflect.TypeOf(limits))

	val := reflect.ValueOf(limits)
	t := reflect.TypeOf(limits)

	for i := 0; i < val.NumField(); i++ {
		if val.Field(i).CanUint() {
			log.Println(t.Field(i).Name, " --> ", val.Field(i).Uint()&0xff)
		}
	}

	return nil
}

func GetCurrentBootedNodeAgentBlacklistedIngressDomainsSLD() error {

	_, connRef, err := GeteBPFAgentRemoteSockConn()
	if err != nil {
		return err
	}

	resp, err := connRef.Get(fmt.Sprintf("http://%s/blacklist/ingress", "unix"))
	if err != nil {
		log.Println("Error connecting to the Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading the response body from the Node Agent")
		return err
	}
	log.Println(string(body))

	return nil
}

func GetCurrentBootedNodeAgentBlacklistedEgressDomainsSLD() error {
	_, connRef, err := GeteBPFAgentRemoteSockConn()
	if err != nil {
		return err
	}

	resp, err := connRef.Get(fmt.Sprintf("http://%s/blacklist/egress", "unix"))
	if err != nil {
		log.Println("Error connecting to the Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading the response body from the Node Agent")
		return err
	}
	log.Println(string(body))

	return nil
}

func UnblockDomain(domain string) error {
	_, connRef, err := GeteBPFAgentRemoteSockConn()
	if err != nil {
		return err
	}

	resp, err := connRef.Get(fmt.Sprintf("http://%s/whitelist?domain=%s", "unix", domain))
	if err != nil {
		log.Println("Error connecting to the Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return err
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading the response body from the Node Agent")
		return err
	}
	log.Println(string(body))

	return nil
}

func GetMaliciousDetectedProcessCtOnNode() error {
	_, connRef, err := GeteBPFAgentRemoteSockConn()
	if err != nil {
		return err
	}

	resp, err := connRef.Get(fmt.Sprintf("http://%s/malProcessCt", "unix"))
	if err != nil {
		log.Println("Error connecting to the Node Agent Local Unix Socket, please make sure the Node Agent is running and the stream socket is healthy", err.Error())
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error reading the response body from the Node Agent")
		return err
	}
	log.Println(string(body))

	return nil
}
