from typing import Any
import pandas as pd 
import os, time 
from pathlib import Path 
import numpy as np 
import matplotlib.pyplot as plt 
from functools import wraps 

# model build 
import tensorflow as tf
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_curve, auc, classification_report, precision_recall_curve, confusion_matrix
from keras import Sequential, layers
import tf2onnx, onnx 

column_names = [
    "user_ip", "domain", "timestamp", "attack", "request", "len", 
    "subdomains_count", "w_count", "w_max", "entropy", "w_max_ratio", 
    "w_count_ratio", "digits_ratio", "uppercase_ratio", "time_avg", 
    "time_stdev", "size_avg", "size_stdev", "throughput", "unique", 
    "entropy_avg", "entropy_stdev"
]

GPU: Any = tf.config.list_physical_devices("GPU")
if len(GPU) > 0:
    print(f'training the model on GPU {GPU} {tf.config.list_physical_devices("GPU")}')
    for gpu in tf.config.list_physical_devices("GPU"):
        tf.config.experimental.set_memory_growth(gpu, True)
else:
    print("Using the default cpu runtime ", tf.config.list_physical_devices())

class Features(object):

    def __init__(self) -> None:
        self.path = os.path.join(os.getcwd(),'datasets', 'dataset.csv')
        self.shuffleSize = 12_000 

    def readDataset(self, batchSize) -> None: 
        def parseData(record) -> Any:
            # process all the feature engineering and transform for the featyres 
            values = tf.strings.split(record, ',')
            total_chars = tf.strings.to_number(values[5], out_type=tf.float32)
            chars_in_subdomain = tf.strings.to_number(values[6], out_type=tf.float32)
            numerical_chars = tf.cast(tf.strings.length(tf.strings.regex_replace(values[4], r'\D', '')), dtype=tf.float32)
            uppercase_chars =  tf.cast(tf.strings.length(tf.strings.regex_replace(values[4], r'[^A-Z]', '')), dtype=tf.float32)
            domain_entropy = tf.strings.to_number(values[9], out_type=tf.float32)
            dots_in_domain = tf.cast(tf.strings.length(tf.strings.regex_replace(values[4], r'[^.]', '')), dtype=tf.float32)
            longest_label = tf.strings.to_number(values[8], out_type=tf.float32)
            average_label =  tf.cast(total_chars / (chars_in_subdomain + 1), dtype=tf.float32)

            # generate the input scalar vector for the DNN 
            features = [total_chars, chars_in_subdomain, numerical_chars, uppercase_chars,
                domain_entropy, dots_in_domain, longest_label, average_label]

            # standard scalar transform
            label = tf.cond(tf.equal(values[3], "True"), lambda: 1.0, lambda : 0.0)
            return tf.convert_to_tensor(features, dtype=tf.float32), label

            
        dataset = tf.data.TextLineDataset(self.path)
        dataset = dataset.map(parseData, num_parallel_calls=tf.data.experimental.AUTOTUNE)
        dataset = dataset.shuffle(buffer_size=10_000)
        dataset = dataset.batch(batch_size=batchSize)
        dataset = dataset.prefetch(buffer_size=tf.data.experimental.AUTOTUNE)
        return dataset

strategy = tf.distribute.MirroredStrategy()


with strategy.scope():
    model = Sequential() 
    model.add(layers.InputLayer(shape=(8, )))
    model.add(layers.Dense(10, activation='relu'))
    model.add(layers.Dense(8, activation='relu'))
    model.add(layers.Dense(1, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])


features = Features()
train_dataset = features.readDataset(batchSize=128_000)
train_data = train_dataset.take(80) # batch training for 80 % of the data 
test_data = train_dataset.skip(80) 
model.fit(train_data, epochs=5, verbose=1)

onnx_model, _ = tf2onnx.convert.from_keras(model=model, input_signature=(tf.TensorSpec([None, 8], tf.float32),))
onnx.save(onnx_model, "dns_sec.onnx")

y_true = []
y_pred = []

for features, labels in test_data:
    y_true.extend(labels.numpy())
    predictions = model.predict(features)
    y_pred.extend(predictions)
    

y_true = np.array(y_true)
y_pred = np.array(y_pred)

# ROC Curve
fpr, tpr, _ = roc_curve(y_true, y_pred)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
plt.plot([0, 1], [0, 1], color='navy', linestyle='--')
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curve')
plt.legend(loc='lower right')
plt.grid(True)
plt.show()

def onnxBuild(func) -> any:
    @wraps(func)
    def wrapper(*args, **kwargs) -> None: 
        print(os.getpid(), tf.__version__) 
        func(pid=os.getpid(), tf_version=tf.__version__)
    return wrapper
 

@onnxBuild
def builder(*args, **kwargs) -> None:
    for key,val in kwargs.items(): print(key,"=",val) 


# onnx_model = tf2onnx.convert.from_keras(model, input_signature, opset=13)
# onnx.save(onnx_model, "model.onnx")
if __name__ == "__main__": 
    builder()
