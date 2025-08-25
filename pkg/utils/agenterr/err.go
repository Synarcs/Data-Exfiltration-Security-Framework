package agenterr

// defines the core format for global errores emit by node agent in runtime

const ()

type AgentError struct {
	Type          string
	Message       string
	DetailedCause string
	Error         error
}

func EmitNewError(err error, errorType string, message string) AgentError {
	return AgentError{
		Type:          errorType,
		Message:       message,
		DetailedCause: err.Error(),
		Error:         err,
	}
}
