#!/usr/bin/env python
# coding: utf-8

# In[1]:

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
from keras.optimizers import Adam
import tf2onnx, onnx, keras 
import math, re , requests as rq 


# In[2]:
GPU: Any = tf.config.list_logical_devices("GPU")
if len(GPU) > 0:
    print(f'training the model on GPU {GPU} {tf.config.list_logical_devices("GPU")}')
        # tf.config.experimental.set_memory_growth(gpu, True)
else:
    print("Using the default cpu runtime ", tf.config.list_physical_devices())


# In[3]:
def calculate_entropy(domain: str) -> float:
    prob = pd.Series(list(domain)).value_counts(normalize=True)
    entropy = -np.sum(prob * np.log2(prob))
    return entropy


# In[4]:


out = os.path.join(os.getcwd(),'datasets', 'combined.csv')


# In[4]:


column_names_det = [
    "user_ip", "domain", "timestamp", "attack", "request", "len", 
    "subdomains_count", "w_count", "w_max", "entropy", "w_max_ratio", 
    "w_count_ratio", "digits_ratio", "uppercase_ratio", "time_avg", 
    "time_stdev", "size_avg", "size_stdev", "throughput", "unique", 
    "entropy_avg", "entropy_stdev"
]

column_names = [
    "id", "domain"
]

combined_columns = [
    "domain", "subdomain", "total_dots", "total_dots_subdomain", "total_chars", "total_chars_subdomain", "number", 
    "upper", "lower", "special", "labels", "max_label_length", "labels_average", "entropy", "attack"
]

def process(data, id):
    chunk = data[data['attack'] == False]

    cols_to_drop = [col for col in column_names_det if col != 'request']
    
    chunk.drop(columns=cols_to_drop, inplace=True)
    chunk.dropna(inplace=True)
    
    
    chunk['request'] = chunk['request']
    chunk['subdomain'] = chunk['request'].apply(lambda xx: ''.join(xx.split('.')[:-2]))
        
    chunk['total_dots'] = chunk['request'].apply(lambda x: str(x).count("."))
    chunk['total_dots_subdomain'] =  chunk['total_dots'] - 1
            
    chunk['total_chars'] = chunk['request'].str.len() - chunk['total_dots']
    chunk['total_chars_subdomain'] = chunk['subdomain'].str.len() - chunk['total_dots_subdomain']
            
    chunk['number'] = chunk['request'].str.count(r'\d')      # Counts digits
    chunk['upper'] = chunk['request'].str.count(r'[A-Z]') 
    chunk['lower'] = chunk['request'].str.count(r'[a-z]') 
    chunk['special'] = chunk['request'].str.count(r'[!@#$%^&*]') 
        
    chunk['labels'] = chunk['request'].str.split('.').apply(lambda xx: len(xx))
    chunk['max_label_length'] = chunk['request'].apply(lambda x: max(len(word) for word in x.split('.')))
    chunk['labels_average'] = chunk.apply(lambda row: row['total_chars'] / row['labels'], axis=1)
    chunk['labels_average'] = chunk['labels_average'].astype(np.float32)

    chunk['entropy'] = chunk['request'].apply(calculate_entropy)
    chunk['attack'] = False
        
        
    id += 1
    chunk.to_csv(out, mode='a', header=False, index=False)

# In[25]:
def process_mal(data, id):
    chunk = data[data['attack'] == True]

    cols_to_drop = [col for col in column_names_det if col != 'request']
    
    chunk.drop(columns=cols_to_drop, inplace=True)
    chunk.dropna(inplace=True)
    
    chunk['request'] = chunk['request']
    chunk['subdomain'] = chunk['request'].apply(lambda xx: ''.join(xx.split('.')[:-2]))
        
    chunk['total_dots'] = chunk['request'].apply(lambda x: str(x).count("."))
    chunk['total_dots_subdomain'] =  chunk['total_dots'] - 1
            
    chunk['total_chars'] = chunk['request'].str.len() - chunk['total_dots']
    chunk['total_chars_subdomain'] = chunk['subdomain'].str.len() - chunk['total_dots_subdomain']
            
    chunk['number'] = chunk['request'].str.count(r'\d')      # Counts digits
    chunk['upper'] = chunk['request'].str.count(r'[A-Z]') 
    chunk['lower'] = chunk['request'].str.count(r'[a-z]') 
    chunk['special'] = chunk['request'].str.count(r'[!@#$%^&*]') 
        
    chunk['labels'] = chunk['request'].str.split('.').apply(lambda xx: len(xx))
    chunk['max_label_length'] = chunk['request'].apply(lambda x: max(len(word) for word in x.split('.')))
    chunk['labels_average'] = chunk.apply(lambda row: row['total_chars'] / row['labels'], axis=1)
    chunk['labels_average'] = chunk['labels_average'].astype(np.float32)

    chunk['entropy'] = chunk['request'].apply(calculate_entropy)
    chunk['attack'] = True
        
        
    id += 1
    
    chunk.to_csv(out, mode='a', header=False, index=False)
            # table = plt.table(cellText=desc.values, 
            #                  colLabels=desc.columns, 
            #                  rowLabels=desc.index, 
            #                  cellLoc='center', 
            #                  loc='center')
        
            # table.scale(2.5, 2.5) 
            # table.auto_set_font_size(True)
            # table.set_fontsize(30)
        


# In[36]:


def process_mal_sync(chunk):
    chunk.drop_duplicates(subset='request', inplace=True)
    
    chunk['request'] = chunk['request']
    chunk['subdomain'] = chunk['request'].apply(lambda xx: ''.join(xx.split('.')[:-2]))
        
    chunk['total_dots'] = chunk['request'].apply(lambda x: str(x).count("."))
    chunk['total_dots_subdomain'] =  chunk['total_dots'] - 1
            
    chunk['total_chars'] = chunk['request'].str.len() - chunk['total_dots']
    chunk['total_chars_subdomain'] = chunk['subdomain'].str.len() - chunk['total_dots_subdomain']
            
    chunk['number'] = chunk['request'].str.count(r'\d')      # Counts digits
    chunk['upper'] = chunk['request'].str.count(r'[A-Z]') 
    chunk['lower'] = chunk['request'].str.count(r'[a-z]') 
    chunk['special'] = chunk['request'].str.count(r'[!@#$%^&*]') 
        
    chunk['labels'] = chunk['request'].str.split('.').apply(lambda xx: len(xx))
    chunk['max_label_length'] = chunk['request'].apply(lambda x: max(len(word) for word in x.split('.')))
    chunk['labels_average'] = chunk.apply(lambda row: row['total_chars'] / row['labels'], axis=1)
    chunk['labels_average'] = chunk['labels_average'].astype(np.float32)

    chunk['entropy'] = chunk['request'].apply(calculate_entropy)
    chunk['attack'] = True
        
        
    # print(chunk.head())
    chunk.to_csv(out, mode='a', header=False, index=False)

### only keep this for vis the node agent in user space in go has parallel I/O over this we dont need this in ds 
path = os.path.join(os.getcwd(),'datasets', 'top-1m.csv')
data = pd.read_csv(path, chunksize= 10_000, names=column_names,delimiter=",")

for chunk in data:
    print(chunk.head(20)) 
    break


# In[92]:


path = os.path.join(os.getcwd(),'datasets', 'dataset_modified.csv')
data = pd.read_csv(path, chunksize= 50_000, names=column_names_det,delimiter=",", on_bad_lines='skip')

id = 0 
for chunk in data: 
    print('writing cleaned dataset chunk for malicious samples', os.getpid(), id)
    process_mal(chunk, id)
    id += 1
    


# In[56]:


path = os.path.join(os.getcwd(),'datasets', 'dataset.csv')
data = pd.read_csv(path, chunksize= 50_000, names=column_names_det,delimiter=",", on_bad_lines='skip')

id = 0 
for chunk in data: 
    # print('writing cleaned dataset chunk for malicious samples', os.getpid(), id)
    if id > 12: break 
    # print(chunk.columns)
    process(chunk, id)
    id += 1
    


# ## Dataset Processing for malicious generated datasets using dnscat dnsteal and DET and raw exf 

# In[37]:


mal = pd.read_csv('datasets/mal.csv')
mal.rename(columns={'Domain': "request"}, inplace=True)

process_mal_sync(mal)


# In[57]:


path = os.path.join(os.getcwd(),'datasets', 'combined.csv')
data = pd.read_csv(path, chunksize= 50_000, names=combined_columns,delimiter=",", on_bad_lines='skip')

id = 0 
b, m = 0, 0 
for chunk in data: 
    print('processing chunk :: ', id)
    id += 1
    bn = chunk[chunk['attack'] == True]
    dn = chunk[chunk['attack'] == False]
    b += bn.shape[0] 
    m += dn.shape[0] 

print("benign samples :: ", b)
print("malicious samples :: ", m)


print(f'sample ratio for benign {(b + m) / b}%')
print(f'sample ratio for malicious {(b + m) / m}%')

total_records = b + m
print(f'total records {b + m}')


# ## train the model

# In[7]:


{combined_columns[i]: i for i in range(len(combined_columns))}


# In[ ]:





# In[5]:


class Features(object):
    def __init__(self) -> None:
        self.path = os.path.join(os.getcwd(),'datasets', 'combined.csv')
        self.shuffleSize = 12_000  # You can adjust the shuffle buffer size if needed

    def readDetDataset(self, batchSize) -> None: 
        def parseData(record) -> Any:
            values = tf.strings.split(record, ',')
            
            def safe_float_conversion(value):
                try:
                    return tf.strings.to_number(value, out_type=tf.float32)
                except Exception:
                    return tf.constant(0.0)  # Default value if conversion fails
            
            # Process features with safe conversion
            total_chars = safe_float_conversion(values[4])
            total_chars_subdomain = safe_float_conversion(values[5])
            number = safe_float_conversion(values[6])
            upper = safe_float_conversion(values[7])
            entropy = safe_float_conversion(values[13])
            total_dots = safe_float_conversion(values[2])
            max_label_length = safe_float_conversion(values[11])
            labels_average = safe_float_conversion(values[12])
        
            features = [total_chars, total_chars_subdomain, number, upper,
                    entropy, total_dots, max_label_length, labels_average]
    
            # Standard scalar transform
            label = tf.cond(tf.equal(values[14], "True"), lambda: 1.0, lambda : 0.0)
            return tf.convert_to_tensor(features, dtype=tf.float32), label
        
        # Read dataset and shuffle before batching
        dataset = tf.data.TextLineDataset(self.path)
        dataset = dataset.map(parseData, num_parallel_calls=tf.data.experimental.AUTOTUNE)
        
        # Shuffle the entire dataset (set the buffer size based on memory availability)
        dataset = dataset.shuffle(buffer_size=10_000)
        
        # Batch the dataset
        dataset = dataset.batch(batch_size=batchSize)
        
        # Prefetch data for performance optimization
        dataset = dataset.prefetch(buffer_size=tf.data.experimental.AUTOTUNE)
        
        return dataset


# In[6]:


features = Features()
batch_size = 8_000

train_dataset = features.readDetDataset(batchSize=batch_size)

total_batches = 1260643 // batch_size

train_batches = int(total_batches * 0.8)
test_batches = total_batches - train_batches 

# Split into training and test data
train_data = train_dataset.take(train_batches)
test_data = train_dataset.skip(train_batches)


# In[7]:



strategy = tf.distribute.MirroredStrategy()


with strategy.scope():
    model = Sequential() 
    model.add(layers.InputLayer(shape=(8,)))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(1, activation='sigmoid'))
    
    model.compile(optimizer=Adam(learning_rate=0.0005), loss='binary_crossentropy', metrics=['accuracy', 'precision', 'recall'])

model.fit(train_data, epochs=20, verbose=1)


# In[27]:


for batch_features, batch_labels in test_data.take(1):
    print(batch_labels)


# In[43]:


results = model.evaluate(test_data, verbose=1)

print(results)
loss = results[0]
accuracy = results[1]
precision = results[2]
recall = results[3]

print(f"Test Loss: {loss:.4f}")
print(f"Test Accuracy: {accuracy:.4f}")
print(f"Test Precision: {precision:.4f}")
print(f"Test Recall: {recall:.4f}")


# In[32]:

def getFeatureDomain(vec: str):
    total_dots = vec.count('.')
    total_chars = len(vec) - total_dots 
    subdomain = vec.split('.')[:-2]  # Assuming the last two parts are the domain and TLD (e.g., 'bleed.io')
    total_dots_subdomain = total_dots - 2
    total_chars_subdomain = sum(len(part) for part in subdomain)  # Total length of all subdomains combined
    number = sum(c.isdigit() for c in vec)
    upper = sum(c.isupper() for c in vec)
    entropy = calculate_entropy(vec)
    labels = vec.split('.')
    max_label_length = max(len(label) for label in labels)
    labels_average = sum(len(label) for label in labels) / len(labels)
    features = [total_chars, total_chars_subdomain, number, upper, entropy, total_dots, max_label_length, labels_average]
    return np.array(features, dtype=np.float32)

def calculate_entropy(domain: str):
    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]
    return -sum(p * math.log(p, 2) for p in prob)

domain = "ipv4-check-perf.radar.cloudflare.com"
features = getFeatureDomain(domain)
features


# In[33]:


feature_vector = features.reshape(1, -1)  
feature_vector.shape


# In[34]:


feature_vector


# In[35]:


predicted_prob = model.predict(feature_vector)[0, 0]
predicted_prob


# In[13]:


onnx_model_path = "dns_sec.onnx"
model.output_names=['output']
input_signature = (tf.TensorSpec([None, 8], tf.float32),)
model.save('dns_sec.h5')
#onnx_model, _ = tf2onnx.convert.from_keras(model=model, input_signature=input_signature, output_path=onnx_model_path)


# In[14]:


onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=input_signature)
with open(onnx_model_path, "wb") as f:
    f.write(onnx_model.SerializeToString())