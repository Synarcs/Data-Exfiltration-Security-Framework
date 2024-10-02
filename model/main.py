import os 
import pandas as pd 
import numpy as np 
from sklearn.preprocessing import LabelEncoder, LabelBinarizer
from sklearn.metrics import confusion_matrix, precision_recall_curve, precision_score
import torch.nn as nn 
from typing import Dict, List
from functools import lru_cache, wraps 


class Feature(object):
    
    def __init__(self) -> None:
        pass 

    @lru_cache(1 << 10)
    def extractFeature(self): pass 

class ModelTrain(object):

    def __init__(self) -> None:
        pass
