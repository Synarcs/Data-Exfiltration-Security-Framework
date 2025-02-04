import  sys 
import onnxruntime as ort
import math
import numpy as np 

sys.path.append(__name__) 

model = '../dns_sec.onnx'
session = ort.InferenceSession(model) 

input_name = session.get_inputs()[0].name
output_name = session.get_outputs()[0].name

def raw_inference(domain: str) -> bool:
     def getFeatureDomain(vec: str):
         total_chars = len(vec)
         subdomain = vec.split('.')[:-2]  # Assuming the last two parts are the domain and TLD (e.g., 'bleed.io')
         total_chars_subdomain = sum(len(part) for part in subdomain)  # Total length of all subdomains combined
         number = sum(c.isdigit() for c in vec)
         upper = sum(c.isupper() for c in vec)
         entropy = calculate_entropy(vec)
         total_dots = vec.count('.')
         labels = vec.split('.')
         max_label_length = max(len(label) for label in labels)
         labels_average = sum(len(label) for label in labels) / len(labels)
         features = [total_chars, total_chars_subdomain, number, upper, entropy, total_dots, max_label_length, labels_average]
         return np.array(features, dtype=np.float32)
     def calculate_entropy(domain: str):
         prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
         return -sum(p * math.log(p, 2) for p in prob)
     input_features = getFeatureDomain(domain)
     input_features = input_features.reshape(1, -1) # flatten over (1, 8)
     print(input_features.shape)
     
     predict = session.run([output_name], {input_name: input_features})
     print("Mal" if predict[0][0][0] > 0.5 else "Benign")
     return True if predict[0][0][0] > 0.5 else False


if __name__ == '__main__':
    print(raw_inference('paaae14y.t.bleed.io'))