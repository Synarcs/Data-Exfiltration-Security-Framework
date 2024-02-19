
import torch 
import torch.nn as nn 
import os


class ModelTrained(nn.Module):
    def __init__(self):
        super()
        self.in_features: int = 8
        self.out_features: int = 2

    def train_model(self):
        l1 = nn.Linear(in_features=self.in_features, out_features=self.out_features, bias=False)
        print(l1.parameters())
