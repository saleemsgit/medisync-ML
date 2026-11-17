# MediSync ML — Document Processing and Security Experiments

A collection of Python ML and computer-vision modules developed for the MediSync project. The code explores document processing, visual verification, user-behaviour analysis, and network anomaly detection.

## Technology stack

**Python · FastAPI · OpenCV · PyTorch · Keras · scikit-learn · EasyOCR · Presidio · spaCy**

## Repository layout

The implementation is nested under **MediSync-ML-main/**:

- **Model API/** — FastAPI application, model artifacts, and dependencies
- **Function01/** — network anomaly experiment and dataset assets
- **Function 02/**, **Function 03/**, **Function04/** — additional module-specific experiments

## Capabilities explored

- Text extraction and privacy-aware document redaction
- PDF/image processing and seal verification
- Signature and other image-detection workflows
- User and typing behaviour anomaly experiments
- Network-traffic anomaly monitoring

These components are research/prototype functionality. Their readiness and required model files vary by module.

## Start the API locally

Use a suitable Python virtual environment and install the module's requirements:

~~~bash
cd "MediSync-ML-main/Model API"
python -m pip install -r requirements.txt
uvicorn main:app --reload
~~~

Some modules may require additional system packages, OCR models, and local dataset/model paths.

## API credentials

If a feature needs Google Gemini, supply **GEMINI_API_KEY** through the runtime environment. Never hard-code API keys or commit a secrets file. Previously committed credentials should be revoked or rotated.

## Disclaimer

This repository contains experimental ML and security-related tooling. Results and error rates should be independently evaluated before production or clinical use.
