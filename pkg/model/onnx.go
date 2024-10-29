package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
)

type OnnxModel struct{}

const (
	DEEP_LEXICAL_INFERENCING  = iota
	STATIC_BENIGN_INFERENCING // node agent found no further deep lexical analysis required its benign and can be procceed to leave the user space
)

/*
Tells the node agent go routeines to call the remote inference server deep learning model for enhanced scanning
*/
func (onnx *OnnxModel) StaticRuntimeChecks(features [][]float32, direction bool) int {
	if features[0][2] == 0 && features[0][3] == 0 {
		return STATIC_BENIGN_INFERENCING
	}
	return DEEP_LEXICAL_INFERENCING
}

func (onnx *OnnxModel) Evaluate(features interface{}, protocol string, direction bool) bool {

	switch protocol {
	case "DNS":
		dnsFeatures, ok := features.([]DNSFeatures)
		if !ok {
			log.Panic("The Required features needs to adher to the protocol definition")
		}
		processRemoteUnixInference := func(featureVectorsFloat [][]float32, direction bool) (bool, error) {
			client, conn, err := GetInferenceUnixClient(direction)
			if err != nil {
				panic(err.Error())
			}

			defer conn.Close()

			for _, dnsFeature := range dnsFeatures {
				if utils.GetKeyPresentInCache(dnsFeature.Tld) {
					return false, nil
				}
			}

			inferRequest := InferenceRequest{
				// pass all the 8 features which define the input layer for the inference in the onnx model
				Features: featureVectorsFloat,
			}

			requestPayload, err := json.Marshal(inferRequest)
			if err != nil {
				log.Fatalf("Error while generating the onnx remote inference request payload  %v", err)
			}
			resp, err := client.Post(fmt.Sprintf("http://%s/onnx/dns", "unix"), "application/json", bytes.NewBuffer(requestPayload))
			if err != nil {
				log.Printf("Error while evaluating the onnx model for the dns features %v", err)
				return false, err
			}

			defer resp.Body.Close()

			payload, err := io.ReadAll(resp.Body)

			if err != nil {
				log.Printf("Error while evaluating the onnx model for the dns features %v", err)
				return false, err
			}

			var inferenceResponse InferenceResponse
			err = json.Unmarshal(payload, &inferenceResponse)

			if err != nil {
				log.Printf("Error while unmarshalling the onnx inference response %v", err)
				return false, err
			}

			if utils.DEBUG {
				log.Println("Received inference from remote unix socket server ", inferenceResponse, inferenceResponse.ThreatType)
			}

			if inferenceResponse.ThreatType {
				// add in the threat cache map for nested lru
				// marked all the dns features as malicious
				for _, dnsFeature := range dnsFeatures {
					utils.UpdateDomainBlacklistInCache(dnsFeature.Tld, dnsFeature.Fqdn)
				}
			}
			return true, nil
		}

		featureVectorsFloat := GenerateFloatVectors(dnsFeatures)
		if onnx.StaticRuntimeChecks(featureVectorsFloat, dnsFeatures[0].IsEgress) == DEEP_LEXICAL_INFERENCING {
			eval, err := processRemoteUnixInference(featureVectorsFloat, direction)
			if err != nil {
				log.Printf("Errpr in processing inference from remote unix socket  %v", err)
				return false
			}
			return eval

		} else {
			return true
		}
	default:
		log.Println("the protocol not supported or missing the onnx model for evaluation")
		return false
	}
}

func ConnectRemoteInferenceSocket(path string) (*OnnxModel, error) {
	return nil, nil
}
