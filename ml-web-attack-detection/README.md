# ML Pipeline for Web-Based Attack Detection (CIC-IDS2017)

## 1. Project Overview
This repository contains an end-to-end Machine Learning pipeline designed to detect web-layer attacks (Brute Force, Cross-Site Scripting [XSS], and SQL Injection) from network traffic flows using the `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` subset of the CIC-IDS2017 dataset.

---

## 2. Directory Structure
ids_project/
├── data/                  # Place the raw CSV dataset here
│   └── Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv
├── models/                # Saved model and scaler artifacts (.joblib)
│   ├── rf_web_attack_model.joblib
│   └── scaler.joblib
├── reports/               # Generated evaluation plots and final PDF report
│   ├── evaluation_plots.png
│   └── Report.pdf
├── main.py                # Standalone end-to-end pipeline script
├── README.md              # Project documentation and execution guide
└── requirements.txt       # Environment dependencies

---

## 3. Setup & Installation

### Prerequisites
* Python 3.10+ installed

### Environment Setup
1. Navigate to the project directory:
   cd ids_project

2. Create and activate a virtual environment:
   # On Windows:
   python -m venv venv
   venv\Scripts\activate

   # On macOS / Linux:
   python3 -m venv venv
   source venv/bin/activate

3. Install required dependencies:
   pip install -r requirements.txt

4. Dataset Setup:
   * Download the dataset archive (MachineLearningCSV.zip) from the UNB CIC-IDS2017 Repository: https://www.unb.ca/cic/datasets/ids-2017.html
   * Place the file `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` directly into the `data/` folder.

---

## 4. How to Run the Pipeline
Run the complete pipeline from the project root:
python main.py

### Script Execution Workflow:
* Cleans missing values (NaN), infinities (inf), and metadata identifiers.
* Encodes binary labels (0 = Benign, 1 = Web Attack).
* Performs a stratified 80/20 train/test split and scales features.
* Trains a RandomForestClassifier with balanced class weighting.
* Saves the trained model and scaler to the `models/` directory using joblib.
* Evaluates model performance (Precision, Recall, F1-Score) and saves the Confusion Matrix & Feature Importance plots to `reports/evaluation_plots.png`.

---

## 5. Tools, Libraries & Disclosures
* Language & Core Libraries: Python 3, Pandas, NumPy, Scikit-Learn, Matplotlib, Seaborn, Joblib
* Dataset: Canadian Institute for Cybersecurity (CIC-IDS2017), University of New Brunswick
* AI Assistance: Gemini was utilized for architectural scaffolding, error handling review, and report structuring.