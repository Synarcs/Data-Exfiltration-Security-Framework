'''
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
'''
import onnxruntime as ort 
import time
from pathlib import Path
from argparse import ArgumentParser
import numpy as np 

def test_quantize_inference(qt_iter: int) -> None:
    model_path = "../dns_sec_qint8.onnx"
    non_quantize_path = "../dns_sec.onnx"
    print(f'testing the qt benchmark for iter {qt_iter}')
    
    session = ort.InferenceSession(Path(model_path), providers=["CPUExecutionProvider"])

    input_name = session.get_inputs()[0].name
    output_name = session.get_outputs()[0].name

    st = time.time()
    for i in range(qt_iter):
        input_features = np.random.rand(8).astype(np.float32).reshape(1, -1)
        _ = session.run([output_name], {input_name: input_features})[0]
    
    print('inference speed for onnx quantize model ', time.time() - st) 
    st = time.time()

    for i in range(qt_iter):
        input_features = np.random.rand(8).astype(np.float32).reshape(1, -1)
        _ = session.run([output_name], {input_name: input_features})[0]
    
    print('inference speed for onnx model ', time.time() - st)

if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-s", "--stress", type=int, required=False, default=(1 << 12), help="Run the stress test on the for n iter of inference on qt int8 input size")

    args = parser.parse_args()

    test_quantize_inference(args.stress) 