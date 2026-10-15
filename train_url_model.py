
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "data" / "balanced_urls.csv"
MODEL_PATH = ROOT / "artifacts" / "raw_url_model.joblib"
RANDOM_STATE = 42


def main():
    print("Loading raw URL dataset...")
    df = pd.read_csv(DATA_PATH, usecols=["url", "label"])

    # Normalize text and labels.
    df["url"] = df["url"].astype("string").str.strip()
    df["label"] = df["label"].astype("string").str.strip().str.lower()

    df = df.dropna(subset=["url", "label"])
    df = df[df["url"].str.len() > 0]
    df = df[df["label"].isin(["legitimate", "phishing"])]

    # Remove duplicate URLs so repeated records do not cross the split.
    df = df.drop_duplicates(subset=["url"]).reset_index(drop=True)

    X = df["url"]
    y = df["label"]

    print(f"Usable unique URLs: {len(df)}")
    print("\nClass counts:")
    print(y.value_counts().to_string())

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=y,
    )

    pipeline = Pipeline([
        (
            "tfidf",
            TfidfVectorizer(
                analyzer="char",
                ngram_range=(3, 5),
                min_df=2,
                max_features=250_000,
                sublinear_tf=True,
                dtype="float32",
            ),
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=1000,
                class_weight="balanced",
                random_state=RANDOM_STATE,
            ),
        ),
    ])

    print(f"\nTraining rows: {len(X_train)}")
    print(f"Testing rows: {len(X_test)}")
    print("Training model; this may take a few minutes...")

    pipeline.fit(X_train, y_train)
    predictions = pipeline.predict(X_test)

    print("\nAccuracy:", round(accuracy_score(y_test, predictions), 4))
    print("\nClassification report:")
    print(
        classification_report(
            y_test,
            predictions,
            labels=["legitimate", "phishing"],
            zero_division=0,
        )
    )

    print("Confusion matrix (actual rows, predicted columns):")
    print(
        confusion_matrix(
            y_test,
            predictions,
            labels=["legitimate", "phishing"],
        )
    )

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "model": pipeline,
            "classes": pipeline.classes_.tolist(),
            "dataset": DATA_PATH.name,
            "feature_method": "character TF-IDF, n-grams 3-5",
        },
        MODEL_PATH,
        compress=3,
    )

    print(f"\nSaved model to: {MODEL_PATH}")


if __name__ == "__main__":
    main()
