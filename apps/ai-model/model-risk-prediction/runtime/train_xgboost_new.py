#!/usr/bin/env python3
import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "Model"
sys.path.insert(0, str(MODEL_DIR))

from xgboost_model import main as train_main

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Force retrain instead of using existing artifacts")
    args = parser.parse_args()
    train_main(force_retrain=args.force)
