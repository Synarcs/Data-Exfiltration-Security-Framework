
ONNX_MNT_PATH: str = "/run/dnsobelisk"


ONNX_INFERENCE_UNIX_SOCKET_EGRESS:str = f"{ONNX_MNT_PATH}/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_INGRESS:str = f"{ONNX_MNT_PATH}/onnx-inference-in.sock"


# ensure this is protected on controller with required mac, lsm and secured privileges
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_EGRESS:str = "/etc/powerdns/onnx-inference-out.sock"
ONNX_INFERENCE_UNIX_SOCKET_CONTROLLER_INGRESS:str = "/etc/powerdns/onnx-inference-in.sock"
