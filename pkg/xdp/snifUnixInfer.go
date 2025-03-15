package xdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strconv"

	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/events/stream"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/model"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/netinet"
	"github.com/Synarcs/Data-Exfiltration-Security-Framework/pkg/utils"
)

func IngressRemoteInferHandler(features [][]float32, rawFeatures []model.DNSFeatures,
	iface *netinet.NetIface, streamClient *stream.StreamProducer) error {
	// process deep lexical analysis from remote unix transport inference server
	inferRequest := model.InferenceRequest{
		// pass all the 8 features which define the input layer for the inference in the onnx model
		Features: features,
	}
	// layer 7 markup over layer 4 unix transport
	ingressClient, _, err := model.GetInferenceUnixClient(false)

	if err != nil {
		log.Printf("Error while evaluating the onnx model for the dns features %v", err)
		return err
	}

	// need this over multiplex transport layer 7 transport
	requestPayload, err := json.Marshal(inferRequest)
	if err != nil {
		log.Fatalf("Error while generating the onnx remote inference request payload  %v", err)
	}
	resp, err := ingressClient.Post(fmt.Sprintf("http://%s/onnx/dns/ing", "unix"), "application/json", bytes.NewBuffer(requestPayload))
	if err != nil {
		log.Printf("Error while evaluating the onnx model for the dns features %v", err)
		return err
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error while evaluating the onnx model for the dns features %v", err)
		return err
	}
	var inferenceResponse model.InferenceResponseIngress
	err = json.Unmarshal(payload, &inferenceResponse)

	if err != nil {
		log.Printf("Error while unmarshalling the onnx inference response %v", err)
		return err
	}

	if utils.DEBUG {
		log.Println("Remote inference over unix ingress socket for transport for node agent ", inferenceResponse)
	}

	for index, resp := range inferenceResponse.ThreatType {
		if resp {
			log.Println("raw feature for malicious payload is ::", rawFeatures[index])
			utils.IngUpdateDomainBlacklistInCache(rawFeatures[index].Tld)
			// putting here 53 the standard DNS port since the socket transport from kernel must be detected before handl itself no need to again check
			// the same port as used for egrres will be used as src port for response from remote c2c malware
			// dont monitro task comm and process struct over ingress traffic
			go events.ExportMaliciousEvents[events.Protocol](events.DNSFeatures(rawFeatures[index]),
				&iface.PhysicalNodeBridgeIpv4, events.DNS, utils.DNS_EGRESS_PORT, nil)
			go streamClient.MarshallStreamThreadEvent(rawFeatures[index], stream.HostNetworkExfilFeatures{
				ExfilPort:        strconv.Itoa(utils.DNS_EGRESS_PORT),
				Protocol:         string(events.DNS),
				PhysicalNodeIpv4: iface.PhysicalNodeBridgeIpv4.String(),
				PhysicalNodeIpv6: iface.PhysicalNodeBridgeIpv6.String(),
			})
		}
	}
	return nil
}
