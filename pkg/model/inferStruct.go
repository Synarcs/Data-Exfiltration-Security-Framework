package model

type InferenceRequest struct {
	Features [][]float32
	Tld      string
	Root     string
}

type InferenceResponse struct {
	ThreatType bool `json:"threat_type"`
}

type InferenceResponseIngress struct {
	ThreatType []bool `json:"threat_type"`
}
