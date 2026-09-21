import os
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

# ---------------------------------------------------------
# 1. Load and Clean Dataset
# ---------------------------------------------------------
file_path = os.path.join("data", "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv")
df = pd.read_csv(file_path, encoding="latin1")

# Clean whitespace from column headers
df.columns = df.columns.str.strip()

print(f"Total Rows: {df.shape[0]:,}")
print(f"Total Columns: {df.shape[1]}")
print("\nTarget Label Distribution:")
print(df['Label'].value_counts())

# Replace infinite values with NaN and drop missing rows
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# Drop redundant or non-informative identifier columns
drop_cols = ['Flow ID', 'Source IP', 'Destination IP', 'Timestamp']
df.drop(columns=[col for col in drop_cols if col in df.columns], inplace=True, errors='ignore')

# Drop columns that have zero variance
zero_variance_cols = [col for col in df.columns if df[col].nunique() <= 1]
df.drop(columns=zero_variance_cols, inplace=True)

print(f"Remaining clean rows: {df.shape[0]:,}")
print(f"Dropped {len(zero_variance_cols)} constant columns.")

# Map BENIGN to 0 and all Web Attacks to 1
df['Binary_Label'] = df['Label'].apply(lambda x: 0 if 'BENIGN' in str(x).upper() else 1)

print("\nBinary Distribution:")
print(df['Binary_Label'].value_counts())

# Separate features (X) and target label (y)
X = df.drop(columns=['Label', 'Binary_Label'])
y = df['Binary_Label']

# ---------------------------------------------------------
# 2. Train-Test Split & Feature Scaling
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, 
    y, 
    test_size=0.2, 
    random_state=42, 
    stratify=y
)

print(f"\nTraining set shape: {X_train.shape}")
print(f"Testing set shape:  {X_test.shape}")

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ---------------------------------------------------------
# 3. Model Training (Random Forest)
# ---------------------------------------------------------
rf_model = RandomForestClassifier(
    n_estimators=100, 
    random_state=42, 
    n_jobs=-1, 
    class_weight='balanced'
)

print("\nTraining Random Forest model...")
rf_model.fit(X_train_scaled, y_train)
print("Model training complete.")

# ---------------------------------------------------------
# 4. Predictions & Evaluation
# ---------------------------------------------------------
y_pred = rf_model.predict(X_test_scaled)

print("\n" + "="*50)
print("CLASSIFICATION REPORT")
print("="*50)
print(classification_report(y_test, y_pred, target_names=["BENIGN (0)", "ATTACK (1)"], digits=4))

# ---------------------------------------------------------
# 5. Visualizations & Saving Plots
# ---------------------------------------------------------
fig, axes = plt.subplots(1, 2, figsize=(16, 6))

# Plot Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=["BENIGN", "ATTACK"])
disp.plot(ax=axes[0], cmap='Blues', values_format='d')
axes[0].set_title("Confusion Matrix")
axes[0].grid(False)

# Plot Top 15 Feature Importances
importances = rf_model.feature_importances_
feature_names = X.columns
feat_importances = pd.Series(importances, index=feature_names).nlargest(15)

feat_importances.sort_values().plot(kind='barh', ax=axes[1], color='steelblue')
axes[1].set_title("Top 15 Most Important Features")
axes[1].set_xlabel("Importance Score")
axes[1].set_ylabel("Features")

plt.tight_layout()

# Save plot to reports folder before displaying
os.makedirs("reports", exist_ok=True)
plt.savefig("reports/evaluation_plots.png", dpi=300)
print("[+] Evaluation plots saved to reports/evaluation_plots.png")
plt.show()

# ---------------------------------------------------------
# 6. Save Model Artifacts with Joblib
# ---------------------------------------------------------
os.makedirs("models", exist_ok=True)
joblib.dump(rf_model, "models/rf_intrusion_detector.joblib")
joblib.dump(scaler, "models/scaler.joblib")
print("[+] Model and Scaler saved to models/ folder successfully!")

# ---------------------------------------------------------
# 7. Real-Time Inference Simulation
# ---------------------------------------------------------
loaded_scaler = joblib.load("models/scaler.joblib")
loaded_model = joblib.load("models/rf_intrusion_detector.joblib")

sample_packet = X_test.iloc[0:1]
sample_packet_scaled = loaded_scaler.transform(sample_packet)

prediction = loaded_model.predict(sample_packet_scaled)
probability = loaded_model.predict_proba(sample_packet_scaled)

label_mapping = {0: "BENIGN (Safe)", 1: "ATTACK (Alert!)"}
print(f"\nLive Packet Analysis:")
print(f"Prediction: {label_mapping[prediction[0]]}")
print(f"Confidence (Benign vs Attack): {probability[0]}")