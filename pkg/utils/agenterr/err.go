/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package agenterr

// defines the core format for global errores emit by node agent in runtime

const ()

type AgentError struct {
	Type          string
	Message       string
	DetailedCause string
	Error         error
}

func EmitNewError(err error, errorType string, message string) *AgentError {
	return &AgentError{
		Type:          errorType,
		Message:       message,
		DetailedCause: err.Error(),
		Error:         err, // maybe nil if there is an forced runtime error generated, with Message displaying the runtime error cause
	}
}
