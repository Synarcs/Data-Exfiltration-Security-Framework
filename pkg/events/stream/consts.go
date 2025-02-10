package stream

const (
	STREAM_THREAT_TOPIC           = "exfil-sec"                      // producer for thread events
	STREAM_THREAT_TOPIC_INFER     = "exfil-sec-infer-controller"     // topic for dynamic domain blacklist on dns server
	STREAM_THREAT_TOPIC_INFER_TCP = "exfil-sec-infer-controller-tcp" // the pdns recursor anaylyze this tcp against the DL ONNX model and infer and update all data plane about the change for data plane to inject dynamic L3 filter
)
