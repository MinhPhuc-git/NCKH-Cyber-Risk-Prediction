#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "Model"
sys.path.insert(0, str(MODEL_DIR))

from base_model import Predictor

MODEL_VERSION = "CYRP_XGBOOST_CVSS_PERCENTILE_V3"

def as_float(v, default=0.0):
    try:
        if v is None or v == "":
            return default
        return float(v)
    except Exception:
        return default

def norm_text(v, default="unknown"):
    if v is None or v == "":
        return default
    return str(v)

def normalize_input(raw: dict) -> dict:
    # Accept both backend feature style and pipeline label style.
    return {
        "cve_id": raw.get("cve_id") or raw.get("CVE_ID") or raw.get("cveId") or "Unknown",
        "cwe_id": raw.get("cwe_id") or raw.get("CWE_ID") or raw.get("cweId") or "Unknown",
        "cvss_version": raw.get("cvss_version") or raw.get("CVSS_cvss_version") or raw.get("cvssVersion") or "unknown",
        "base_score": as_float(raw.get("base_score") or raw.get("CVSS_base_score") or raw.get("baseScore")),
        "av_label": norm_text(raw.get("av_label") or raw.get("CVSS_attack_vector") or raw.get("attackVector")),
        "ac_label": norm_text(raw.get("ac_label") or raw.get("CVSS_attack_complexity") or raw.get("attackComplexity")),
        "pr_label": norm_text(raw.get("pr_label") or raw.get("CVSS_privileges_required") or raw.get("privilegesRequired")),
        "ui_label": norm_text(raw.get("ui_label") or raw.get("CVSS_user_interaction") or raw.get("userInteraction")),
        "scope_label": norm_text(raw.get("scope_label") or raw.get("CVSS_scope") or raw.get("scope")),
        "c_label": norm_text(raw.get("c_label") or raw.get("CVSS_confidentiality") or raw.get("confidentiality")),
        "i_label": norm_text(raw.get("i_label") or raw.get("CVSS_integrity") or raw.get("integrity")),
        "a_label": norm_text(raw.get("a_label") or raw.get("CVSS_availability") or raw.get("availability")),
        "exploitability_score": as_float(raw.get("exploitability_score") or raw.get("CVSS_exploitability_score") or raw.get("exploitabilityScore")),
        "impact_score": as_float(raw.get("impact_score") or raw.get("CVSS_impact_score") or raw.get("impactScore")),
        "severity_label": raw.get("severity_label") or raw.get("baseSeverity") or "Unknown",
    }

def final_priority(prob: float, risk: str) -> str:
    risk_upper = (risk or "").upper()
    if "RẤT" in risk_upper or "CRITICAL" in risk_upper:
        return "CRITICAL"
    if "CAO" in risk_upper or "HIGH" in risk_upper:
        return "HIGH"
    if "TRUNG" in risk_upper or "MEDIUM" in risk_upper:
        return "MEDIUM"
    if prob >= 0.7:
        return "HIGH"
    if prob >= 0.4:
        return "MEDIUM"
    return "LOW"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="xgboost")
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default=None)
    args = ap.parse_args()

    model_dir = ROOT / "Model Result" / "xgboost"
    model_path = model_dir / "xgboost_model.pkl"
    encoder_path = model_dir / "xgboost_encoders.pkl"
    metrics_path = model_dir / "xgboost_metrics.json"
    if not model_path.exists() or not encoder_path.exists() or not metrics_path.exists():
        raise FileNotFoundError(f"Missing trained XGBoost artifacts in {model_dir}. Run runtime/train_xgboost_new.py --force first.")

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    predictor = Predictor(
        model_path=str(model_path),
        encoder_path=str(encoder_path),
        feature_names=metrics.get("feature_names"),
        threshold=metrics.get("tuned_threshold", 0.5),
        risk_thresholds=metrics.get("risk_thresholds"),
        reference_probs=metrics.get("validation_probabilities", []),
    )

    raw = json.loads(Path(args.input).read_text(encoding="utf-8"))
    normalized = normalize_input(raw)
    pred = predictor._predict_data(normalized, verbose=False)
    prob = float(pred.get("Probability") or 0.0)
    risk = pred.get("Risk") or "THẤP"
    out = {
        "cveId": pred.get("CVE_ID"),
        "modelName": "xgboost",
        "modelVersion": MODEL_VERSION,
        "attackProbability": prob,
        "predictedPercentile": pred.get("Percentile"),
        "riskLevel": risk,
        "finalPriority": final_priority(prob, risk),
        "prediction": bool(pred.get("Prediction")),
        "thresholdUsed": pred.get("Threshold_Used"),
        "details": {
            "reasons": pred.get("Reasons", []),
            "riskThresholdsUsed": pred.get("Risk_Thresholds_Used"),
            "rawPrediction": pred,
        },
    }
    text = json.dumps(out, ensure_ascii=False, indent=2)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text)

if __name__ == "__main__":
    main()
