CYRP AI results risk-level UI patch

What it changes:
- Finds the User Web AI/vulnerability result TSX page containing "Mọi severity".
- Replaces the visible Severity dropdown with an AI Risk level dropdown.
- Removes the visible Active/status dropdown.
- Keeps status=ACTIVE as an implicit API query parameter.
- Sorts results by AI risk level rank first, then predictedPercentile / attackProbability.
- Adds a frontend fallback filter by aiPrediction.riskLevel if the backend ignores riskLevel.
