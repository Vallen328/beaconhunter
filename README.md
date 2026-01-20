# BeaconHunter – Analytics for Covert C2 Detection

BeaconHunter is a security analytics prototype designed to identify and prioritize potential command-and-control (C2) beaconing activity in enterprise network telemetry. The system focuses on behavioral patterns rather than static indicators, helping security analysts triage large volumes of events and focus investigation efforts on the most suspicious hosts.

The project combines feature engineering grounded in real-world attacker tradecraft with both supervised and unsupervised machine learning models. Rather than producing binary verdicts, BeaconHunter assigns continuous risk scores that support investigation prioritization in a SOC environment.

## Project Structure
```bash
.
├── data/                  # Training and live evaluation datasets
├── src/                   # Core detection and scoring logic
│   ├── features.py
│   ├── train_detector.py
│   └── score_live_events.py
├── notebooks/              # Exploratory analysis and feature design
├── tests/                  # Sanity tests
├── artifacts/              # Trained model artifacts
├── Dockerfile
├── requirements.txt
├── ANALYST_REPORT.md
├── INTEGRITY.md
├── NOTES.md
```

## Setup
### Local Environment

Create a virtual environment and install dependencies:

```bash
python -m venv venv
source venv\Scripts\activate # Windows
pip install -r requirements.txt
```

### Training the Detector

This script trains supervised and unsupervised models using data/beacon_events_train.csv and writes serialized model artifacts to artifacts/.

```bash
python -m src.train_detector
```

### Scoring Live Events

This script scores events from data/beacon_events_eval_unlabeled.csv and prints host-level risk prioritization to stdout.

```bash
python -m src.score_live_events
```

The scoring pipeline computes:

- Supervised probability scores

- Unsupervised anomaly scores

- Final fused risk scores

Results are aggregated at the host level to support analyst prioritization.

### Running Tests

Run all sanity tests:

```bash
pytest
```

Tests validate:

- Feature engineering correctness

- Pipeline stability

- End-to-end execution safety

## Docker Usage
The default container entrypoint runs the training pipeline; this can be adjusted to score live events as needed.
### Build the Docker Image

```bash
docker build -t beaconhunter .
```

### Run the Training Pipeline
```bash
docker run --rm beaconhunter
```


This executes the full training pipeline inside the container and produces trained artifacts.

Scoring Live Events in Docker

If you modify the Docker entrypoint to run the scoring script, the same command pattern applies:

```bash
docker run --rm beaconhunter
```

## Disclaimer

This project is a prototype intended for educational and evaluation purposes. It is not a production-ready security control and should be used as an analyst decision-support system, not as an autonomous detection mechanism.
