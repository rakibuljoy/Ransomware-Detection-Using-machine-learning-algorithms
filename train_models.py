
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from imblearn.over_sampling import SMOTE
import joblib

# Load dataset
file_path = "data/data_file.csv"  
try:
    data = pd.read_csv(file_path)
except FileNotFoundError:
    raise FileNotFoundError(f"The dataset file was not found at path: {file_path}")

print("Columns in the dataset:", data.columns)


if "Benign" not in data.columns:
    raise KeyError("The 'Benign' column is missing from the dataset. Please check the dataset structure.")


features = [
    "DebugSize", "DebugRVA", "MajorImageVersion", "MajorOSVersion",
    "ExportRVA", "ExportSize", "IatVRA", "MajorLinkerVersion",
    "MinorLinkerVersion", "NumberOfSections", "SizeOfStackReserve",
    "DllCharacteristics", "ResourceSize", "BitcoinAddresses"
]


missing_features = [feature for feature in features if feature not in data.columns]
if missing_features:
    raise KeyError(f"The following features are missing from the dataset: {', '.join(missing_features)}")

X = data[features]
y = data["Benign"]  


class_counts = y.value_counts()
print("\nClass Distribution:")
print(class_counts)

if class_counts.min() / class_counts.max() < 0.8:
    print("\nDataset is imbalanced. Applying SMOTE to balance it.")
    smote = SMOTE(random_state=42)
    X, y = smote.fit_resample(X, y)
    print("\nAfter SMOTE Class Distribution:")
    print(pd.Series(y).value_counts())
else:
    print("\nDataset is balanced. Proceeding without SMOTE.")


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)


rf = RandomForestClassifier(random_state=42, n_estimators=100, max_depth=10, min_samples_split=5, min_samples_leaf=2)
dt = DecisionTreeClassifier(random_state=42, max_depth=10, min_samples_split=5, min_samples_leaf=2)
xgb = XGBClassifier(random_state=42, n_estimators=100, max_depth=6, learning_rate=0.1, eval_metric="logloss")


rf.fit(X_train, y_train)
dt.fit(X_train, y_train)
xgb.fit(X_train, y_train)


def ensemble_predict(models, X):
    predictions = np.array([model.predict(X) for model in models])
    return np.round(np.mean(predictions, axis=0)).astype(int)

models = [rf, dt, xgb]


def evaluate_model(model, X_train, X_test, y_train, y_test):
    train_pred = model.predict(X_train)
    test_pred = model.predict(X_test)
    metrics = {
        "Train Accuracy": accuracy_score(y_train, train_pred),
        "Test Accuracy": accuracy_score(y_test, test_pred),
        "Precision": precision_score(y_test, test_pred),
        "Recall": recall_score(y_test, test_pred),
        "F1-Score": f1_score(y_test, test_pred)
    }
    return metrics


rf_metrics = evaluate_model(rf, X_train, X_test, y_train, y_test)
dt_metrics = evaluate_model(dt, X_train, X_test, y_train, y_test)
xgb_metrics = evaluate_model(xgb, X_train, X_test, y_train, y_test)


y_pred_ensemble = ensemble_predict(models, X_test)
ensemble_metrics = {
    "Test Accuracy": accuracy_score(y_test, y_pred_ensemble),
    "Precision": precision_score(y_test, y_pred_ensemble),
    "Recall": recall_score(y_test, y_pred_ensemble),
    "F1-Score": f1_score(y_test, y_pred_ensemble)
}


conf_matrix = confusion_matrix(y_test, y_pred_ensemble)

print("\nMetrics for Random Forest:")
print(rf_metrics)

print("\nMetrics for Decision Tree:")
print(dt_metrics)

print("\nMetrics for XGBoost:")
print(xgb_metrics)

print("\nMetrics for Ensemble:")
print(ensemble_metrics)

print("\nConfusion Matrix for Ensemble:")
print(conf_matrix)


joblib.dump(models, "models/ensemble_model.pkl")
print("\nModels saved as models/ensemble_model.pkl")