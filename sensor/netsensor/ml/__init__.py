"""
DoS/DDoS window model: training, evaluation and inference (phase D4).

Needs numpy, scikit-learn and xgboost, which live in the ml-service venv:

    ..\\apps\\ml-service\\.venv\\Scripts\\python.exe -m netsensor train ...

The extractor (netsensor/*.py outside this package) stays standard-library
only and never imports from here.
"""

BUNDLE_FORMAT = "dos-model-bundle-v1"

# Detector status shown to analysts. Only TRAINED means a supervised model
# trained on verified, non-synthetic labels.
STATUS_TRAINED = "TRAINED"
STATUS_SYNTHETIC = "SYNTHETIC_TEST_ONLY"
STATUS_HEURISTIC = "HEURISTIC"
STATUS_NOT_TRAINED = "NOT_TRAINED"
