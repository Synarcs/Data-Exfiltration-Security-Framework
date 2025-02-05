#/usr/bin/python3

import signal
import onnxruntime as ort
import numpy as np
import os , asyncio 
import math

model = '../model/dns_sec.onnx'
session = ort.InferenceSession(model) 

if not os.path.exists(model):
    print('the required trained onnx model not found')
    os.exit(signal.SIGKILL) 

input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

DEBUG = True

class Inference:
    def __init__(self) -> None: 
        super().__init__()

    @staticmethod
    def predict(input_features) -> None:
        if input_features.shape != (1, 8):
            print('cannot infer a broken vector tensor for model inference')
            return 

        return True if session.run([output_name], {input_name: input_features})[0][0][0] > 0.5 else False 
    

if DEBUG:
    if __name__ == '__main__':
        infer = Inference()
        infer.raw_inference('paaae14y.t.bleed.io')