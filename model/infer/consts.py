

ONNX_INFERENCE_UNIX_SOCKET_EGRESS = "/run/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_INGRESS = "/run/onnx-inference-in.sock"


# ensure this is protected on controller with required mac, lsm and secured privileges
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS = "/tmp/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS = "/tmp/onnx-inference-in.sock"
