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

/*
The []DNSFeatures is for a single dns packet covering the the entire dns packet queries
each array resemble the dns request, addon, auth, answer section fqdn domain to perform enhance scanning of those features
*/
func (onnx *OnnxModel) GenerateInputLayerFeatures(features *[]DNSFeatures) error {
	return nil
}

func (onnx *OnnxModel) Evaluate(features interface{}, protocol string) bool {

	var castedFeatures []DNSFeatures = features.([]DNSFeatures)

	switch protocol {
	case "DNS":
	default:
		log.Println("the protocol not supported or missing the onnx model for evaluation")
		return false
	}

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
	resp, err := client.Post(fmt.Sprintf("http://%s/onnx", "unix"), "application/json", bytes.NewBuffer(requestPayload))
	if err != nil {
		log.Printf("Error while evaluating the onnx model for the dns features %v", err)
		return false
	}

	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Printf("Error while evaluating the onnx model for the dns features %v", err)
		return false
	}

	log.Println("Received inference from remote unix socket server ", string(payload))

	for _, feature := range castedFeatures {
		// no need for go routine to do task parallelism on go routine and later sync via channels
		if !EvaluateModelAgainstSingleFeature(feature) {
			utils.UpdateDomainBlacklistInCache(feature.Tld, feature.Fqdn)
		}
	}
	return true
}

func EvaluateModelAgainstSingleFeature(feature DNSFeatures) bool {
	if feature.UCaseCount == 0 && feature.NumberCount == 0 && feature.UCaseCount >= 0 {
		return true
	}
	return true
}

func ConnectRemoteInferenceSocket(path string) (*OnnxModel, error) {
	return nil, nil
}
