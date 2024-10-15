package model

import (
	"errors"
	"log"
	"os"

	"github.com/Data-Exfiltration-Security-Framework/pkg/utils"
)

type OnnxModel struct {
	LoadedOnnxModel interface{}
}

func (onnx *OnnxModel) Evaluate(features interface{}, protocol string) bool {

	var castedFeatures []DNSFeatures = features.([]DNSFeatures)
	switch protocol {
	case "DNS":
	default:
		log.Println("the protocol not supported or missing the onnx model for evaluation")
		return false
	}

	for _, feature := range castedFeatures {
		// no need for go routine to do task parallelism on go routine and later sync via channels
		if !EvaluateModelAgainstSingleFeature(feature) {
			utils.UpdateDomainBlacklistInCache(feature.Fqdn, utils.DomainNodeAgentCacheBlock{
				TLD:            utils.ExtractTldFromDomain(feature.Fqdn),
				CompleteDomain: feature.Fqdn,
			})
		}
	}
	return true
}

func EvaluateModelAgainstSingleFeature(feature DNSFeatures) bool {
	return true
}

func LoadOnnxModelToMemory(path string) (*OnnxModel, error) {
	val, err := os.Stat("/home/ubuntu/model.onnx")
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// TODO: Load the model and make sure it exist as a bundled onnx model
			log.Println("the Required saved model not found")
		}
	}
	return &OnnxModel{
		LoadedOnnxModel: val,
	}, nil
}
