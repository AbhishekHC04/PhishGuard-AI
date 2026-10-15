# PhishGuard AI

**An Explainable AI-Powered Phishing URL Detection System**

PhishGuard AI is a cybersecurity portfolio project that combines rule-based URL analysis with machine learning to estimate whether a URL may be associated with phishing.

## Features

- **Heuristic URL Analysis:** Identifies suspicious URL patterns and assigns a risk score.
- **Machine Learning Detection:** Uses character-level TF-IDF and Logistic Regression to classify URLs.
- **Phishing Probability:** Displays the model-estimated phishing probability.
- **Batch URL Scanning:** Analyzes multiple URLs from a CSV file.
- **Interactive Dashboard:** Built with Streamlit.
- **REST API:** Uses FastAPI to provide rule-based URL analysis.
- **Automated Testing:** Includes tests using pytest.

## Technology Stack

Python · Streamlit · FastAPI · Scikit-learn · Pandas · Joblib · Pytest

## Project Structure

```text
PhishGuard-AI/
├── artifacts/              # Trained models (generated locally)
├── data/                   # Datasets (stored locally)
├── phishguard/
│   ├── __init__.py
│   ├── batch_scanner.py
│   ├── ml_predictor.py
│   ├── raw_url_predictor.py
│   └── url_analyzer.py
├── tests/
│   ├── test_batch_scanner.py
│   ├── test_ml_predictor.py
│   └── test_url_analyzer.py
├── api.py
├── app.py
├── train_model.py
├── train_url_model.py
├── sample_urls.csv
├── .gitignore
└── README.md
```

## Installation and Setup

### 1. Clone the repository

Replace the placeholder with your GitHub repository URL after publishing the project.

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd PhishGuard-AI
```

### 2. Create a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install streamlit pandas scikit-learn joblib fastapi "uvicorn[standard]" pytest
```

## Dataset and Model Training

The raw-URL machine learning model expects a CSV file at:

`data/balanced_urls.csv`

The dataset must contain these columns:
- `url` — the URL text.
- `label` — the URL classification label.

The dataset used during development was obtained from:

https://github.com/Hassan-Albattra/URL_Phishing_Detection_Dataset

Review the dataset's licensing and usage terms before redistributing it.

### Train the model

After placing the dataset in the expected location, run:

```powershell
python train_url_model.py
```

The trained model is saved to:

`artifacts/raw_url_model.joblib`

The dashboard and batch scanner require this model artifact to make machine learning predictions.

**Note:** The dataset and generated model files are excluded from Git through `.gitignore`. You must obtain the dataset and generate the model locally.

## Run the Dashboard

From the project root, activate your virtual environment and run:

```powershell
python -m streamlit run app.py
```

Open the local URL displayed in your terminal, usually:

http://localhost:8501

The dashboard supports individual URL analysis and batch scanning from a CSV file.

## Run the REST API

Start the FastAPI service:

```powershell
python -m uvicorn api:app --reload
```

Open the interactive API documentation:

http://127.0.0.1:8000/docs

### Available API endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/` | API status |
| GET | `/health` | Health check |
| POST | `/analyze` | Rule-based URL analysis |

The current API provides heuristic URL analysis. Machine learning predictions are integrated into the dashboard and batch scanner, not the API endpoint.

## Model Evaluation

The raw-URL classification model achieved **96.92% accuracy** on a stratified random holdout from the development dataset.

| Metric | Result |
|---|---:|
| Test accuracy | 96.92% |
| Test samples | 67,945 |
| Legitimate URLs correctly classified | 32,904 |
| Legitimate URLs incorrectly classified as phishing | 1,096 |
| Phishing URLs incorrectly classified as legitimate | 997 |
| Phishing URLs correctly classified | 32,948 |

Precision, recall, and F1-score for both classes were approximately 97%.

### Confusion Matrix

Rows represent actual classes; columns represent predicted classes.

| Actual class | Predicted legitimate | Predicted phishing |
|---|---:|---:|
| Legitimate | 32,904 | 1,096 |
| Phishing | 997 | 32,948 |

**Important:** These results come from a random holdout of the development dataset. They do not guarantee performance on unseen domains, future phishing campaigns, or real-world traffic.

## Run Tests

With the virtual environment activated, run:

```powershell
python -m pytest -v
```

The development test suite previously passed all 13 tests.

## Security and Limitations

- The application analyzes URL text and does not visit submitted websites.
- A machine learning prediction is an estimate, not proof that a website is safe or malicious.
- Heuristic risk scores and ML predictions are separate signals and may disagree.
- The model can produce false positives and false negatives.
- Results depend on the quality and representativeness of the training data.
- Do not use this project as the sole security control for sensitive activities.

## Future Improvements

- Integrate machine learning predictions into the REST API.
- Add Docker deployment and continuous integration.
- Evaluate the model using time-separated and domain-separated test data.
- Improve explainability and reporting.
- Monitor model performance and false positives.

## Author

Developed as a cybersecurity and machine learning portfolio project.