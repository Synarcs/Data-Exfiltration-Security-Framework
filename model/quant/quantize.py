'''
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
'''
from abc import ABC, abstractmethod
import os, time 
from pathlib import Path
from onnxruntime.quantization import quantize_dynamic, QuantType
from onnxruntime.quantization.preprocess import quant_pre_process
from typing import NoReturn
import onnxruntime as ort 
import numpy as np 

class QuantizeProvider(ABC):
    # quantize the model supporting different backends and cpu backends, to be implemented as per quantize backend requirement 
    def __init__(self):
        super(QuantizeProvider, self).__init__() 

    @abstractmethod
    def quantize_onnx_model(self) -> NoReturn: pass 


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
    preprocessQuantizeOnnxModel()

