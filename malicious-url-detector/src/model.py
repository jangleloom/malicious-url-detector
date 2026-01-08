# THINGS TO DO: 
# 1. Read CSV files from proccessed_dataset.csv 
# 2. For each url, extract numerical components using extract_components from components.py 
# 3. Train logistic regression model to learn malicious vs benign
# 4. Evaluate model performance on test set
# 5. Save trained model for later use 

import pandas as pd
from components import extract_components
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import classification_report, confusion_matrix
from joblib import dump, load
import os

DATAPATH = "data/processed/processed_dataset.csv"
EVAL_MODE = "random"  # Options: "random" or "cross"

def main():
    df = pd.read_csv(DATAPATH)
    
    # RANDOM SPLIT EVALUATION
    if EVAL_MODE == "random":
        components_list = df["url"].apply(extract_components)
        components_df = pd.DataFrame(components_list.tolist())

        X = components_df.select_dtypes(include=["number"]).fillna(0)
        y = df["label"].astype(int)

        X_train, X_test, y_train, y_test = train_test_split(
            X,
            y,
            test_size=0.2,
            random_state=42,
            stratify=y
        )

    # CROSS-SOURCE EVALUATION
    elif EVAL_MODE == "cross":
        train_df = df[df["source"].isin(["phishtank", "tranco"])].copy()
        test_df  = df[df["source"].isin(["urlhaus", "tranco"])].copy()

        # Balance TRAIN
        train_mal = train_df[train_df["label"] == 1]
        train_ben = train_df[train_df["label"] == 0].sample( n=len(train_mal), random_state=42)
        train_df = pd.concat([train_mal, train_ben], ignore_index=True)

        # Balance TEST
        test_mal = test_df[test_df["label"] == 1]
        test_ben = test_df[test_df["label"] == 0].sample(n=len(test_mal), random_state=42)
        test_df = pd.concat([test_mal, test_ben], ignore_index=True)

        # Feature extraction
        train_components = train_df["url"].apply(extract_components)
        test_components  = test_df["url"].apply(extract_components)

        X_train = pd.DataFrame(train_components.tolist())
        y_train = train_df["label"].astype(int)

        X_test = pd.DataFrame(test_components.tolist())
        y_test = test_df["label"].astype(int)

        # Keep numerical values only 
        X_train = X_train.select_dtypes(include=["number"]).fillna(0)
        X_test  = X_test.select_dtypes(include=["number"]).fillna(0)
        # Ensure test set has same columns as train set ie. missing columns filled with 0 
        X_test  = X_test.reindex(columns=X_train.columns, fill_value=0)

    else:
        raise ValueError(f"Unknown EVAL_MODE: {EVAL_MODE}")

    # Train logistic regression model
    base = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42, C=0.01)
    # model = CalibratedClassifierCV(base, method="sigmoid", cv=5)
    model = base
    model.fit(X_train, y_train)


    # Evaluate model
    y_pred = model.predict(X_test)
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, y_pred))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, digits=4))

    # ADD THIS CODE HERE:
    feature_importance = pd.DataFrame({
        'feature': X_train.columns,
        'importance': abs(base.coef_[0])  # Use base, not model
    }).sort_values('importance', ascending=False)

    print("\nTop 10 Most Important Features:")
    print(feature_importance.head(10))



    # Save trained model
    MODEL_PATH = "models/logistic_regression_model.joblib"
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    dump({"model": model, "columns": list(X_train.columns)}, MODEL_PATH)
    print(f"Trained model saved to {MODEL_PATH}")

    # --- For debugging purposes, print dataset stats ---
    mal = df[df['label'] == 1]
    benign = df[df['label'] == 0]
    print(df.head())
    print(f"Total URLs: {len(df)}")
    print(f"Malicious URLs: {len(mal)}")
    print(f"Benign URLs: {len(benign)}")
    print(f"Test set shape: {X_test.shape}, {y_test.shape}")


if __name__ == "__main__":
    main()  