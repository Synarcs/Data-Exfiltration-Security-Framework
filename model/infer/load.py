import onnxruntime as ort
import numpy as np
import os , asyncio 

model = '../dns_sec.onnx'
session = ort.InferenceSession(model) 

input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

print(input_name, output_name) 

test_data = np.array([[0, 33, 2, 0, 3.6950207, 3, 16, 0]], dtype=np.float32) 
predict = session.run([output_name], {input_name: test_data})

print(predict)

if __name__ == "__test__": pass 
