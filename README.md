# Synthetic Nervous System (SNS)

**Training BERT to Detect Emotional Manipulation and Adversarial Behavior in AI Systems**

Current AI lacks the ability to recognize manipulative behavior the way a human empath would. This project builds an emotional safety layer for Large Language Models by detecting psychological manipulation patterns.

## Overview
The Synthetic Nervous System is a multimodal adversarial detection framework that combines:
- **Psychology & NLP** — Detecting emotional manipulation in conversations
- **Cybersecurity** — Detecting adversarial patterns in network traffic
- **Machine Learning** — Fusing both signals into a single detection system

## Results
| Model                    | Accuracy | Precision | Recall | F1   |
|--------------------------|----------|-----------|--------|------|
| BERT (Conversational)    | **96%**  | 0.97      | 0.96   | 0.96 |
| Random Forest (Network)  | In Progress | -      | -      | -    |
| Fusion (Multimodal)      | In Progress | -      | -      | -    |

BERT was fine-tuned on 200 labeled conversations and achieved **96% accuracy** on unseen test data.

## Six-Vector Manipulation Taxonomy
- **emotional_invalidation** – Dismissing emotional experience
- **gaslighting** – Making someone doubt their perception
- **blame_shifting** – Redirecting responsibility
- **goalpost_moving** – Continuously changing parameters
- **trust_violation** – Exploiting established context
- **adversarial_prompting** – Jailbreak-style attacks

## Project Structure
synthetic-nervous-system/
├── sns_bert.db
├── sns_network.db
├── SNS_BERT_Training.ipynb
├── sns_rf_train.py
├── sns_fusion_eval.py
└── sns_bert_confusion_matrix.png


## How to Run
1. Generate the databases:
   ```bash
   python sns_bert_db.py
   python sns_network_traffic.py

2. Train BERT in Google Colab using SNS_BERT_Training.ipynb with T4 GPU.

Stack
Python • PyTorch • Hugging Face Transformers • BERT • scikit-learn • SQLite • Google Colab
Author: Stacey Freeman
Master's Candidate in Artificial Intelligence & Machine Learning
Status: BERT completed • Random Forest & Fusion in progress