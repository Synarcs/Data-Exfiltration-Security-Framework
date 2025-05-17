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
from keras.metrics import BinaryAccuracy, FalseNegatives, FalsePositives, TruePositives, TrueNegatives, Precision, Recall, F1Score, Accuracy, AUC
from keras.optimizers import Adam
import tf2onnx, onnx, keras 

# %%
GPU: Any = tf.config.list_logical_devices("GPU")
if len(GPU) > 0:
    print(f'training the model on GPU {GPU} {tf.config.list_logical_devices("GPU")}')
    # tf.config.experimental.set_memory_growth(gpu, True)
else:
    print("Using the default cpu runtime ", tf.config.list_physical_devices())


# %%
def calculate_entropy(domain: str) -> float:
    prob = pd.Series(list(domain)).value_counts(normalize=True)
    entropy = -np.sum(prob * np.log2(prob))
    return entropy


# %%
out = os.path.join(os.getcwd(),'datasets', 'combined.csv')

# %%
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


# %% [markdown]
# ### Benign dataset feature extract 
#

# %%
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
            # table = plt.table(cellText=desc.values, 
            #                  colLabels=desc.columns, 
            #                  rowLabels=desc.index, 
            #                  cellLoc='center', 
            #                  loc='center')
        
            # table.scale(2.5, 2.5) 
            # table.auto_set_font_size(True)
            # table.set_fontsize(30)
        


# %%
def process_mal(data, id):
    chunk = data[data['attack'] == True]
    cols_to_drop = [col for col in column_names_det if col != 'request']
    
    chunk.drop(columns=cols_to_drop, inplace=True)
    chunk.dropna(inplace=True)
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
        


# %%
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
            # table = plt.table(cellText=desc.values, 
            #                  colLabels=desc.columns, 
            #                  rowLabels=desc.index, 
            #                  cellLoc='center', 
            #                  loc='center')
        
            # table.scale(2.5, 2.5) 
            # table.auto_set_font_size(True)
            # table.set_fontsize(30)
        


# %% [markdown]
# ### Cisco Top 1 million dataset

# %%
### only keep this for vis the node agent in user space in go has parallel I/O over this we dont need this in ds 

path = os.path.join(os.getcwd(),'datasets', 'top-1m.csv')
data = pd.read_csv(path, chunksize= 10_000, names=column_names,delimiter=",")

for chunk in data:
    print(chunk.head(20)) 
    break

# %%
path = os.path.join(os.getcwd(),'datasets', 'dataset.csv')
data = pd.read_csv(path, chunksize= 50_000, names=column_names_det,delimiter=",", on_bad_lines='skip')

id = 0 
for chunk in data: 
    print('writing cleaned dataset chunk for malicious samples', os.getpid(), id)
    process_mal(chunk, id)
    id += 1
    


# %%
path = os.path.join(os.getcwd(),'datasets', 'dataset.csv')
data = pd.read_csv(path, chunksize= 50_000, names=column_names_det,delimiter=",", on_bad_lines='skip')

id = 0 
for chunk in data: 
    # print('writing cleaned dataset chunk for malicious samples', os.getpid(), id)
    if id > 37: break 
    # print(chunk.columns)
    process(chunk, id)
    id += 1
    


# %% [markdown]
# ## Dataset Processing for malicious generated datasets using dnscat dnsteal and DET and raw exf 

# %%
mal = pd.read_csv('datasets/mal.csv')
mal.rename(columns={'Domain': "request"}, inplace=True)

process_mal_sync(mal)


# %%
mal_image_image =  pd.read_csv('datasets/mal_image.csv', chunksize= 50_000,delimiter=",", on_bad_lines='skip')
chunkId = 0 
for chunk in mal_image_image:
    print('processing the chunk ', chunkId)
    chunk.rename(columns={'Domain': "request"}, inplace=True)
    process_mal_sync(chunk)
    chunkId += 1    

# %%
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

# %% [markdown]
# ## train the model

# %%
{combined_columns[i]: i for i in range(len(combined_columns))}



# %%
import nltk
nltk.download('words')
from nltk.corpus import words

"information" in words.words()


# %%
class Features(object):
    def __init__(self) -> None:
        self.path = os.path.join(os.getcwd(),'datasets', 'combined.csv')
        self.total_records = 3_777_227
        self.shuffle_size = self.total_records

    def readDetDataset(self, batchSize) -> None: 
        def parseData(record) -> Any:
            values = tf.strings.split(record, ',')
            
            def safe_float_conversion(value):
                try:
                    return tf.strings.to_number(value, out_type=tf.float32)
                except Exception:
                    return tf.constant(0.0)  
            
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
    
            label = tf.cond(tf.equal(values[14], "True"), lambda: 1.0, lambda : 0.0)
            return tf.convert_to_tensor(features, dtype=tf.float32), label
        
        dataset = tf.data.TextLineDataset(self.path)
        dataset = dataset.map(parseData, num_parallel_calls=tf.data.experimental.AUTOTUNE)
        
        dataset = dataset.shuffle(buffer_size=self.shuffle_size, reshuffle_each_iteration=True)
        
        dataset = dataset.batch(batch_size=batchSize)
        
        dataset = dataset.prefetch(buffer_size=tf.data.experimental.AUTOTUNE)
        
        return dataset



# %%
features = Features()
batch_size = 32_000
dataset = features.readDetDataset(batchSize=batch_size)

# Compute splits
total_batches = features.total_records // batch_size
train_batches = int(total_batches * 0.7)
val_batches = int(total_batches * 0.15)
test_batches = total_batches - train_batches - val_batches

# Split deterministically after shuffle
train_data = dataset.take(train_batches)
val_data = dataset.skip(train_batches).take(val_batches)
test_data = dataset.skip(train_batches + val_batches)

# %%
train_data

# %%
malicious_count = 0
benign_count = 0
for _, label in train_data:
    malicious_count += tf.reduce_sum(tf.cast(label == 1, tf.int32)).numpy()
    benign_count += tf.reduce_sum(tf.cast(label == 0, tf.int32)).numpy()

print(f"Malicious samples in train data: {malicious_count}")
print(f"Benign samples in train data: {benign_count}")

# %%
malicious_count = 0
benign_count = 0
for _, label in val_data:
    malicious_count += tf.reduce_sum(tf.cast(label == 1, tf.int32)).numpy()
    benign_count += tf.reduce_sum(tf.cast(label == 0, tf.int32)).numpy()

print(f"Malicious samples in val data: {malicious_count}")
print(f"Benign samples in val data: {benign_count}")

# %%
malicious_count = 0
benign_count = 0
for _, label in test_data:
    malicious_count += tf.reduce_sum(tf.cast(label == 1, tf.int32)).numpy()
    benign_count += tf.reduce_sum(tf.cast(label == 0, tf.int32)).numpy()

print(f"Malicious samples in test data: {malicious_count}")
print(f"Benign samples in test data: {benign_count}")

# %%
strategy = tf.distribute.MirroredStrategy()

metrics = [TruePositives(name='tp'), FalsePositives(name='fp'), FalseNegatives(name='fn'), TrueNegatives(name='tn'), BinaryAccuracy(name='ac'), 
           Precision(name='precision'), Recall(name='recall'), AUC(name='auc')]
with strategy.scope():
    model = Sequential() 
    model.add(layers.InputLayer(shape=(8,)))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(16, activation='relu'))
    model.add(layers.Dense(1, activation='sigmoid'))
    
    model.compile(optimizer=Adam(learning_rate=0.001), loss='binary_crossentropy', 
                          metrics=metrics)

model.summary()
print(metrics)

# %%
history = model.fit(train_data, validation_data=val_data ,epochs=25, verbose=1)

# %%
print(history.history.keys())

# %%
plt.plot(history.history['ac'])
plt.plot(history.history['val_ac'])
plt.title('Model Accuracy')
plt.ylabel('accuracy')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='lower right')
plt.show()

# %%
plt.plot(history.history['loss'])
plt.plot(history.history['val_loss'])
plt.title('Model Training Loss')
plt.ylabel('Loss')
plt.xlabel('epoch')
plt.legend(['train', 'val'], loc='upper right')
plt.show()

# %%
plt.plot(history.history['fp'])
plt.plot(history.history['fn'])
plt.title('Model Prediction Metrics')
plt.ylabel('Prediction')
plt.xlabel('epoch')
plt.legend(['False Positive', 'False Negative'], loc='upper right')
plt.show()

# %%
plt.plot(history.history['tp'])
plt.plot(history.history['tn'])
plt.title('Model Prediction Metrics')
plt.ylabel('Prediction')
plt.xlabel('epoch')
plt.legend(['True Positive', 'True Negative'], loc='lower right')
plt.show()

# %%
plt.plot(history.history['precision'])
plt.plot(history.history['recall'])
plt.title('Model Prediction Metrics')
plt.ylabel('Prediction')
plt.xlabel('epoch')
plt.legend(['Precision', 'Recall'], loc='lower right')
plt.show()

# %%
print(history.history.keys())

# %%
test_data

# %%
results = model.evaluate(test_data, verbose=1)

# %%
# true_labels = []
# predict = []

# for feature, label in test_data.as_numpy_iterator():
#     true_labels.append(label)
    
#     pred = model.predict(feature)  
#     pred = pred[:, 0]
#     predict.append(pred)

true_labels = []
predictions = []

for features, labels in test_data:
    preds = model.predict(features, verbose=0).flatten()   # shape: (batch_size,)
    predictions.extend(preds)
    true_labels.extend(labels.numpy().flatten())           # shape: (batch_size,)

# %%
test_data.(20)

# %%
true_labels_mod = true_labels  # already flat
predict_mod = predictions      # already flat

print(len(true_labels_mod))
print(len(predict_mod))

# %%
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import f1_score, precision_score, recall_score

thresholds = np.linspace(0.15, 0.9, 50)
f1_scores = []
precisions = []
recalls = []

for thresh in thresholds:
    preds_bin = (np.array(predict_mod) >= thresh).astype(int)
    f1_scores.append(f1_score(true_labels_mod, preds_bin))
    precisions.append(precision_score(true_labels_mod, preds_bin))
    recalls.append(recall_score(true_labels_mod, preds_bin))

plt.figure(figsize=(8, 6))
plt.plot(thresholds, f1_scores, marker='o', label='F1 Score', color='purple')
plt.plot(thresholds, precisions, marker='x', label='Precision', color='blue')
plt.plot(thresholds, recalls, marker='s', label='Recall', color='green')

plt.title("Precision, Recall, and F1 Score vs. Threshold")
plt.xlabel("Threshold")
plt.ylabel("Score")
plt.grid(True)
plt.legend()
plt.tight_layout()
plt.show()

# %%
import seaborn as sns
from sklearn.metrics import confusion_matrix

threshold = 0.95
preds_bin = (np.array(predict_mod) >= threshold).astype(int)
cm = confusion_matrix(true_labels_mod, preds_bin)

plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', cbar=False,
            xticklabels=['Predicted 0', 'Predicted 1'],
            yticklabels=['True 0', 'True 1'])
val = 0.85
plt.title(f'Confusion Matrix at Threshold {val}')
plt.ylabel('True Label')
plt.xlabel('Predicted Label')
plt.show()

# %%
true_labels = np.array(true_labels_mod).flatten()
predictions = np.array(predict_mod).flatten()

# %%
fpr, tpr, thresholds = roc_curve(true_labels, predictions)
roc_auc = auc(fpr, tpr)

plt.figure()
plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)

# Add threshold labels every 1/5th
for i in range(0, len(fpr), max(1, len(fpr)//5)):
    plt.text(fpr[i], tpr[i], f'{thresholds[i]:.2f}', fontsize=8, color='black', ha='center')

plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('Receiver Operating Characteristic')
plt.legend(loc="lower right")
plt.grid(True)
plt.show()

# %%
print("Sample predictions:", predictions[20:100])
print("Sample true labels:", true_labels[20:100])

# %%
import math
import re

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

domain = "global.beat.apple.complex.dsdasdsdasdas.cloudflare.net"
features = getFeatureDomain(domain)
features

# %%
feature_vector = features.reshape(1, -1)  
feature_vector.shape

# %%
feature_vector

# %%
predicted_prob = model.predict(feature_vector)[0, 0]
predicted_prob

# %%
onnx_model_path = "dns_sec.onnx"
tensort_model_path = "dns_sec.h5"
model.output_names=['output']
input_signature = (tf.TensorSpec([None, 8], tf.float32),)
model.save(tensort_model_path)
#onnx_model, _ = tf2onnx.convert.from_keras(model=model, input_signature=input_signature, output_path=onnx_model_path)

# %%
onnx_model, _ = tf2onnx.convert.from_keras(model, input_signature=input_signature)
with open(onnx_model_path, "wb") as f:
    f.write(onnx_model.SerializeToString())

# %%
import os
if os.path.isfile(onnx_model_path): print("Model Onnx Saved to:: " , os.path.abspath(onnx_model_path))

# %%
if os.path.isfile(tensort_model_path): print("Model Saved to:: " , os.path.abspath(tensort_model_path))

# %%

# %%
