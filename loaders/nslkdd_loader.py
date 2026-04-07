"""
NSL-KDD network intrusion detection loader.

41 features matching the NSL-KDD feature set.  If data/nslkdd.csv is present
it is loaded; otherwise a synthetic equivalent is generated.

Label 1 = attack, 0 = normal.
"""

import os
import numpy as np
import pandas as pd
from sklearn.datasets import make_classification

DATA_PATH = os.path.join("data", "nslkdd.csv")
N_FEATURES = 41
N_SAMPLES = 5000
RANDOM_STATE = 42


def load_nslkdd_data(random_state: int = RANDOM_STATE):
    """Returns (X, y) with X shape (n_samples, 41) and y ∈ {0, 1}."""
    if os.path.exists(DATA_PATH):
        df = pd.read_csv(DATA_PATH)
        y = df.iloc[:, -1].values.astype(int)
        X = df.iloc[:, :-1].values.astype(np.float32)
        return X, y

    # Synthetic fallback
    X, y = make_classification(
        n_samples=N_SAMPLES,
        n_features=N_FEATURES,
        n_informative=20,
        n_redundant=10,
        n_classes=2,
        weights=[0.65, 0.35],
        flip_y=0.01,
        random_state=random_state,
    )
    return X.astype(np.float32), y
