

ONNX_INFERENCE_UNIX_SOCKET_EGRESS = "/run/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/run/onnx-inference-in.sock"


# ensure this is protected on controller with required mac, lsm and secured privileges
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS = "/etc/powerdns/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS = "/etc/powerdns/onnx-inference-in.sock"
