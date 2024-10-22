package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
)

type OnnxModel struct{}

/*
The []DNSFeatures is for a single dns packet covering the the entire dns packet queries
each array resemble the dns request, addon, auth, answer section fqdn domain to perform enhance scanning of those features
*/
func (onnx *OnnxModel) GenerateInputLayerFeatures(features *[]DNSFeatures) error {
	return nil
}

func (onnx *OnnxModel) Evaluate(features interface{}, protocol string) bool {

	switch protocol {
	case "DNS":
		_, ok := features.([]DNSFeatures)
		if !ok {
			log.Panic("The Required features needs to adher to the protocol definition")
		}
		processRemoteUnixInference := func() (bool, error) {
			client, conn, err := GetInferenceUnixClient()
			if err != nil {
				panic(err.Error())
			}

			defer conn.Close()

			inferRequest := InferenceRequest{
				// pass all the 8 features which define the input layer for the inference in the onnx model
				Features: [][]float32{
					// questions
					{
						1.0, 2.0, 3.0, 4.0,
					},
					// answers
					{
						2.0, 3.0, 4.0, 5.0,
					},
					// additional
					{
						2.0, 3.0, 4.0, 5.0,
					},
					// auth
					{
						1.0, 2.1212,
					},
				},
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

			log.Println("Received inference from remote unix socket server ", inferenceResponse, inferenceResponse.ThreatType)

			return true, nil
		}
		eval, err := processRemoteUnixInference()
		if err != nil {
			log.Printf("Errpr in processing inference from remote unix socket  %v", err)
			return false
		}
		return eval
	default:
		log.Println("the protocol not supported or missing the onnx model for evaluation")
		return false
	}
}

func ConnectRemoteInferenceSocket(path string) (*OnnxModel, error) {
	return nil, nil
}
