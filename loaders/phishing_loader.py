"""
UCI Phishing Websites dataset loader.

30 features matching the UCI Phishing Websites feature set.  If
data/phishing.csv is present it is loaded; otherwise a synthetic equivalent
is generated.

Label 1 = phishing, 0 = legitimate.
"""

import os
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

DATA_PATH = os.path.join("data", "phishing.csv")
N_FEATURES = 30
N_SAMPLES = 5000
RANDOM_STATE = 42


def load_phishing_data(random_state: int = RANDOM_STATE):
    """Returns (X, y) with X shape (n_samples, 30) and y ∈ {0, 1}."""
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        y = df.iloc[:, -1].values.astype(int)
        X = df.iloc[:, :-1].values.astype(np.float32)
        return X, y

    # Synthetic fallback
    X, y = make_classification(
        n_samples=N_SAMPLES,
        n_features=N_FEATURES,
        n_informative=15,
        n_redundant=5,
        n_classes=2,
        weights=[0.55, 0.45],
        flip_y=0.01,
        random_state=random_state,
    )
    return X.astype(np.float32), y
