'''
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
'''
from abc import ABC, abstractmethod
import os, time 
from pathlib import Path
from argparse import ArgumentParser
from onnxruntime.quantization import quantize_dynamic, QuantType
from onnxruntime.quantization.preprocess import quant_pre_process
from typing import NoReturn
import onnxruntime as ort 
import numpy as np 

class QuantizeProvider(ABC):
    # quantize the model supporting different backends and cpu backends, to be implemented as per quantize backend requirement 
    @abstractmethod
    def quantize_onnx_model(self) -> NoReturn:
        pass 


def test_quantize_inference() -> None:
    model_path = "../dns_sec_qint8.onnx"
    non_quantize_path = "../dns_sec.onnx"
    
    session = ort.InferenceSession(Path(model_path), providers=["CPUExecutionProvider"])

    input_name = session.get_inputs()[0].name
    output_name = session.get_outputs()[0].name

    st = time.time()
    for i in range(1 << 16):
        input_features = np.random.rand(8).astype(np.float32).reshape(1, -1)
        _ = session.run([output_name], {input_name: input_features})[0]
    
    print('inference speed for onnx quantize model ', time.time() - st) 
    st = time.time()

    non_quantize_session = ort.InferenceSession(non_quantize_path, providers=["CPUExecutionProvider"])
    for i in range(1 << 12):
        input_features = np.random.rand(8).astype(np.float32).reshape(1, -1)
        _ = session.run([output_name], {input_name: input_features})[0]
    
    print('inference speed for onnx model ', time.time() - st)

class CpuOptimiumQuantizer(QuantizeProvider):

    model: Path
    quant_model: str 
    def __init__(self, model_path: str):
        super(CpuOptimiumQuantizer, self).__init__()
        self.model = Path(model_path)
        if not os.path.exists(self.model):
            print(f'the path does not exist to the onnx model {self.model}')


    def quantize_onnx_model(self):
        quant_pre_process(
            input_model=self.model.absolute(),
            output_model_path="dns_sec_qint_preproc.onnx",
            verbose=True
        )

        quantize_dynamic(
            model_input="dns_sec_qint_preproc.onnx",
            model_output="../dns_sec_qint8.onnx",
        )

        os.remove("dns_sec_qint_preproc.onnx")


def preprocessQuantizeOnnxModel() -> None:
    CpuOptimiumQuantizer("../dns_sec.onnx").quantize_onnx_model()


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument('-q', '--quantize', type=bool, required=False, default=True, help="Quantize the onnx model")
    parser.add_argument("-s", "--stress", type=bool, required=False, default=False, help="Run the stress test on the model")

    args = parser.parse_args()
    
    preprocessQuantizeOnnxModel()
    if args.stress:
        test_quantize_inference()

