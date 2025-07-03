/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package inference

type OnnXInference interface {
	InferenceRequeust()
}

type OnnXInferenceTtrpcSock struct {
}

func Init() error {
	_, _, err := GetInferenceUnixClient(true)
	if err != nil {
		return err
	}

	return nil
}

func (ttprc *OnnXInferenceTtrpcSock) Request() error {
	return nil
}
