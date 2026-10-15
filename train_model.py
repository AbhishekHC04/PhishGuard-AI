
from pathlib import Path

import joblib
import pandas as pd

from sklearn.compose import make_column_transformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    accuracy_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import LabelEncoder, StandardScaler


DATA_PATH = Path("data/Phishing.csv")
MODEL_PATH = Path("artifacts/phishing_model.joblib")
RANDOM_STATE = 42


def main():
    print("Loading dataset...")
    df = pd.read_csv(DATA_PATH)

    label_column = "URL_Type_obf_Type"

    # Remove exact duplicate rows.
    df = df.drop_duplicates().copy()

    # Keep only rows with recognized labels.
    df = df[df[label_column].isin(["benign", "phishing"])].copy()

    X = df.drop(columns=[label_column])
    y = df[label_column].map({"benign": 0, "phishing": 1})

    # Keep numeric features and replace infinite values with missing values.
    X = X.select_dtypes(include="number")
    X = X.replace([float("inf"), float("-inf")], float("nan"))

    # Drop columns that contain no usable values.
    X = X.dropna(axis=1, how="all")

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    pipeline = make_pipeline(
        SimpleImputer(strategy="median"),
        RandomForestClassifier(
            n_estimators=200,
            random_state=RANDOM_STATE,
            class_weight="balanced",
            n_jobs=-1,
        ),
    )

    print(f"Training rows: {len(X_train)}")
    print(f"Testing rows: {len(X_test)}")
    print(f"Features: {X.shape[1]}")

    pipeline.fit(X_train, y_train)

    predictions = pipeline.predict(X_test)

    print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["benign", "phishing"],
            zero_division=0,
        )
    )

    print("Confusion matrix (actual rows, predicted columns):")
    print(confusion_matrix(y_test, predictions, labels=[0, 1]))

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": pipeline,
            "feature_columns": X.columns.tolist(),
            "label_mapping": {"benign": 0, "phishing": 1},
        },
        MODEL_PATH,
    )

    print(f"\nModel saved to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
