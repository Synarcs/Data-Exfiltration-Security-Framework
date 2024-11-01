package model

type InferenceRequest struct {
	Features [][]float32
}

type InferenceResponse struct {
	ThreatType bool `json:"threat_type"`
}
