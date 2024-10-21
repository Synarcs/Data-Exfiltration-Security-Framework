package model

import (
	"errors"
	"log"
	"net"
	"os"
	"unsafe"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
)

type OnnxModel struct {
	InferenceUnixListerner net.Conn
}

func (onnx *OnnxModel) Evaluate(features interface{}, protocol string) bool {

	var castedFeatures []DNSFeatures = features.([]DNSFeatures)

	switch protocol {
	case "DNS":
	default:
		log.Println("the protocol not supported or missing the onnx model for evaluation")
		return false
	}

	input := []float32{1.0, 10.0, 100.0, 200.0}
	data := (*[1 << 30]byte)(unsafe.Pointer(&input[0]))[: len(input)*4 : len(input)*4]

	_, err := onnx.InferenceUnixListerner.Write(data)
	if err != nil {
		panic(err.Error())
	}

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

func LoadOnnxModelToMemory(path string, inferenceListener *net.Conn) (*OnnxModel, error) {
	_, err := os.Stat("../../model/dns_sec.onnx")

	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// TODO: Load the model and make sure it exist as a bundled onnx model
			log.Println("the Required saved model not found")
		}
	}

	return &OnnxModel{
		InferenceUnixListerner: *inferenceListener,
	}, nil
}
