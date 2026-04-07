"""
EMBER-style PE malware feature loader.

Generates a synthetic 2381-feature dataset that mirrors the EMBER dataset's
feature space (byte histograms, section info, imports, strings, etc.).
If an actual EMBER dataset CSV is placed at data/ember.csv it will be loaded;
otherwise a fully synthetic dataset is produced via make_classification.
"""

import os
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

DATA_PATH = os.path.join("data", "ember.csv")
N_FEATURES = 2381
N_SAMPLES = 5000
RANDOM_STATE = 42


def load_ember_data(random_state: int = RANDOM_STATE):
    """
    Returns (X, y) where X has shape (n_samples, 2381) and y ∈ {0, 1}.

    Label 1 = malicious, 0 = benign.
    """
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        y = df.iloc[:, -1].values.astype(int)
        X = df.iloc[:, :-1].values.astype(np.float32)
        return X, y

    # Synthetic fallback
    X, y = make_classification(
        n_samples=N_SAMPLES,
        n_features=N_FEATURES,
        n_informative=200,
        n_redundant=100,
        n_classes=2,
        weights=[0.5, 0.5],
        flip_y=0.01,
        random_state=random_state,
    )
    return X.astype(np.float32), y
