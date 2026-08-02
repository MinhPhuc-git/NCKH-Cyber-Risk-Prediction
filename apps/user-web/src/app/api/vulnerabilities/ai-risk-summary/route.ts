import { NextRequest, NextResponse } from 'next/server';

type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

type AnyRecord = Record<string, unknown>;

function asRecord(value: unknown): AnyRecord {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as AnyRecord)
    : {};
}

function getArray(payload: unknown): AnyRecord[] {
  const record = asRecord(payload);

  const candidates = [
    record.items,
    record.predictions,
    record.data,
    record.results,
    record.rows,
    record.records,
  ];

  for (const candidate of candidates) {
    if (Array.isArray(candidate)) {
      return candidate.filter(
        (item): item is AnyRecord =>
          item !== null && typeof item === 'object' && !Array.isArray(item),
      );
    }
  }

  return [];
}

function numberValue(value: unknown): number | null {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return value;
  }

  if (typeof value === 'string' && value.trim()) {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : null;
  }

  return null;
}

function totalValue(payload: unknown, fallback: number): number {
  const record = asRecord(payload);

  return (
    numberValue(record.total) ??
    numberValue(record.count) ??
    numberValue(record.totalItems) ??
    numberValue(record.totalRecords) ??
    fallback
  );
}

function normalizeRiskLevel(value: unknown): RiskLevel | null {
  const level = String(value ?? '').trim().toUpperCase();

  if (level === 'LOW' || level === 'THẤP') {
    return 'LOW';
  }

  if (
    level === 'MEDIUM' ||
    level === 'TRUNG BÌNH' ||
    level === 'TRUNG_BINH'
  ) {
    return 'MEDIUM';
  }

  if (level === 'HIGH' || level === 'CAO') {
    return 'HIGH';
  }

  if (
    level === 'CRITICAL' ||
    level === 'VERY_HIGH' ||
    level === 'VERY HIGH' ||
    level === 'RẤT CAO' ||
    level === 'RAT CAO'
  ) {
    return 'CRITICAL';
  }

  return null;
}

function parseExplanation(value: unknown): AnyRecord {
  if (typeof value === 'string' && value.trim()) {
    try {
      return asRecord(JSON.parse(value));
    } catch {
      return {};
    }
  }

  return asRecord(value);
}

function predictionOf(item: AnyRecord): AnyRecord {
  const direct = asRecord(item.aiPrediction);
  if (Object.keys(direct).length > 0) {
    return direct;
  }

  const snake = asRecord(item.ai_prediction);
  if (Object.keys(snake).length > 0) {
    return snake;
  }

  return asRecord(item.prediction);
}

function riskOf(item: AnyRecord): RiskLevel | null {
  const prediction = predictionOf(item);
  const explanation = parseExplanation(prediction.explanation);

  return (
    normalizeRiskLevel(item.riskLevel) ??
    normalizeRiskLevel(item.risk_level) ??
    normalizeRiskLevel(item.aiRiskLevel) ??
    normalizeRiskLevel(item.finalRiskLevel) ??
    normalizeRiskLevel(item.final_risk_level) ??
    normalizeRiskLevel(item.ai_risk_level) ??
    normalizeRiskLevel(prediction.riskLevel) ??
    normalizeRiskLevel(prediction.risk_level) ??
    normalizeRiskLevel(explanation.riskLevel) ??
    normalizeRiskLevel(explanation.risk_level)
  );
}

function attackProbabilityOf(item: AnyRecord): number | null {
  const prediction = predictionOf(item);
  const explanation = parseExplanation(prediction.explanation);

  return (
    numberValue(item.attackProbability) ??
    numberValue(item.exploitProbability) ??
    numberValue(item.exploit_probability) ??
    numberValue(item.attack_probability) ??
    numberValue(prediction.attackProbability) ??
    numberValue(prediction.attack_probability) ??
    numberValue(explanation.attackProbability) ??
    numberValue(explanation.attack_probability)
  );
}

function percentileOf(item: AnyRecord): number | null {
  const prediction = predictionOf(item);
  const explanation = parseExplanation(prediction.explanation);

  return (
    numberValue(item.predictedPercentile) ??
    numberValue(item.aiPercentile) ??
    numberValue(item.ai_percentile) ??
    numberValue(item.predicted_percentile) ??
    numberValue(item.percentile) ??
    numberValue(prediction.predictedPercentile) ??
    numberValue(prediction.predicted_percentile) ??
    numberValue(prediction.percentile) ??
    numberValue(explanation.predictedPercentile) ??
    numberValue(explanation.predicted_percentile)
  );
}

async function fetchPredictionPage(request: NextRequest, page: number) {
  const url = new URL('/api/ai-predictions', request.url);
  url.searchParams.set('limit', '100');
  url.searchParams.set('page', String(page));

  const response = await fetch(url, {
    method: 'GET',
    cache: 'no-store',
    headers: {
      cookie: request.headers.get('cookie') ?? '',
    },
  });

  const payload = await response
    .clone()
    .json()
    .catch(() => null);

  return { response, payload };
}

export async function GET(request: NextRequest) {
  const first = await fetchPredictionPage(request, 1);

  if (!first.response.ok || !first.payload) {
    return first.response;
  }

  const firstItems = getArray(first.payload);
  const total = totalValue(first.payload, firstItems.length);
  const totalPages = Math.max(1, Math.ceil(total / 100));

  const items = [...firstItems];

  for (let page = 2; page <= totalPages && page <= 20; page += 1) {
    const next = await fetchPredictionPage(request, page);

    if (!next.response.ok || !next.payload) {
      break;
    }

    items.push(...getArray(next.payload));
  }

  const distribution: Record<RiskLevel, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
  };

  let highestAttackProbability: number | null = null;
  let highestPercentile: number | null = null;

  for (const item of items) {
    const risk = riskOf(item);

    if (risk) {
      distribution[risk] += 1;
    }

    const attackProbability = attackProbabilityOf(item);
    if (attackProbability !== null) {
      highestAttackProbability =
        highestAttackProbability === null
          ? attackProbability
          : Math.max(highestAttackProbability, attackProbability);
    }

    const percentile = percentileOf(item);
    if (percentile !== null) {
      highestPercentile =
        highestPercentile === null
          ? percentile
          : Math.max(highestPercentile, percentile);
    }
  }

  return NextResponse.json(
    {
      total,
      loaded: items.length,
      distribution,
      highestAttackProbability,
      highestPercentile,
      calculatedAt: new Date().toISOString(),
    },
    {
      headers: {
        'Cache-Control': 'no-store, max-age=0',
        Pragma: 'no-cache',
      },
    },
  );
}