/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

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
	Protocol   string `json:"protocol"`
}
