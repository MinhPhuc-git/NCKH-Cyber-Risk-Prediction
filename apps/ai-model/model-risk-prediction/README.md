# CYRP model-risk-prediction

This folder contains the cleaned XGBoost + CTI pipeline layout requested for CYRP:

1. `Model/xgboost_model.py` trains XGBoost and writes artifacts to `Model Result/xgboost`.
2. `CTI Collector/Extract_Data_Wazuh.py` extracts `CVE_ID,agent_id` from Wazuh CSV into `CTI Collector/cve_data/LIST_CVE_ID.csv`.
3. `run_pipeline.py` reads the CVE list, downloads Wazuh CTI JSON, extracts CVSS/remediation fields, runs the trained model, and writes result JSON files into `Data User`.
4. Backend DB import from `Data User` is a later integration step; after DB import succeeds, `Data User` JSON files can be deleted.

The old non-XGBoost model files are intentionally not included.
