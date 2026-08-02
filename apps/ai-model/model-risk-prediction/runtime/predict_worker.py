#!/usr/bin/env python3
"""Long-lived JSON-lines prediction worker for CYRP.

The process loads the trained XGBoost artifacts exactly once, then accepts one
request per stdin line:
    {"id": "request-id", "input": { ... model input ... }}

It returns one stdout line:
    {"id": "request-id", "result": { ... CYRP prediction ... }}

All protocol messages are JSON and stdout is flushed after every response.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "Model"
sys.path.insert(0, str(MODEL_DIR))

from base_model import Predictor  # noqa: E402

MODEL_VERSION = "CYRP_XGBOOST_CVSS_PERCENTILE_V3"


def as_float(value: Any, default: float = 0.0) -> float:
    try:
        if value is None or value == "":
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def norm_text(value: Any, default: str = "unknown") -> str:
    if value is None or value == "":
        return default
    return str(value)


def normalize_input(raw: dict[str, Any]) -> dict[str, Any]:
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


def final_priority(probability: float, risk: str) -> str:
    risk_upper = (risk or "").upper()
    if "RẤT" in risk_upper or "CRITICAL" in risk_upper:
        return "CRITICAL"
    if "CAO" in risk_upper or "HIGH" in risk_upper:
        return "HIGH"
    if "TRUNG" in risk_upper or "MEDIUM" in risk_upper:
        return "MEDIUM"
    if probability >= 0.7:
        return "HIGH"
    if probability >= 0.4:
        return "MEDIUM"
    return "LOW"


def load_predictor() -> Predictor:
    model_dir = ROOT / "Model Result" / "xgboost"
    model_path = model_dir / "xgboost_model.pkl"
    encoder_path = model_dir / "xgboost_encoders.pkl"
    metrics_path = model_dir / "xgboost_metrics.json"

    missing = [
        str(path)
        for path in (model_path, encoder_path, metrics_path)
        if not path.exists()
    ]
    if missing:
        raise FileNotFoundError(
            "Missing trained XGBoost artifacts: " + ", ".join(missing)
        )

    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    return Predictor(
        model_path=str(model_path),
        encoder_path=str(encoder_path),
        feature_names=metrics.get("feature_names"),
        threshold=metrics.get("tuned_threshold", 0.5),
        risk_thresholds=metrics.get("risk_thresholds"),
        reference_probs=metrics.get("validation_probabilities", []),
    )


def predict(predictor: Predictor, raw: dict[str, Any]) -> dict[str, Any]:
    normalized = normalize_input(raw)
    prediction = predictor._predict_data(normalized, verbose=False)
    artifact_path = prediction.pop("_saved_path", None)
    probability = float(prediction.get("Probability") or 0.0)
    risk = prediction.get("Risk") or "THẤP"

    return {
        "cveId": prediction.get("CVE_ID"),
        "modelName": "xgboost",
        "modelVersion": MODEL_VERSION,
        "attackProbability": probability,
        "predictedPercentile": prediction.get("Percentile"),
        "riskLevel": risk,
        "finalPriority": final_priority(probability, risk),
        "prediction": bool(prediction.get("Prediction")),
        "artifactPath": artifact_path,
        "thresholdUsed": prediction.get("Threshold_Used"),
        "details": {
            "reasons": prediction.get("Reasons", []),
            "riskThresholdsUsed": prediction.get("Risk_Thresholds_Used"),
            "rawPrediction": prediction,
        },
    }


def emit(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=True, separators=(",", ":")), flush=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="xgboost")
    parser.parse_args()

    try:
        predictor = load_predictor()
    except Exception as error:  # startup must fail loudly for NestJS
        emit({
            "type": "startup-error",
            "error": str(error),
            "traceback": traceback.format_exc(limit=8),
        })
        return 1

    emit({"type": "ready", "modelVersion": MODEL_VERSION})

    for line in sys.stdin:
        stripped = line.strip()
        if not stripped:
            continue

        request_id: str | None = None
        try:
            envelope = json.loads(stripped)
            request_id = str(envelope.get("id") or "")
            raw_input = envelope.get("input")
            if not request_id:
                raise ValueError("Missing request id")
            if not isinstance(raw_input, dict):
                raise ValueError("Request input must be a JSON object")

            emit({
                "id": request_id,
                "result": predict(predictor, raw_input),
            })
        except Exception as error:
            emit({
                "id": request_id,
                "error": str(error),
                "traceback": traceback.format_exc(limit=8),
            })

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
