// ─── AURA Dataset Evaluator ───────────────────────────────────────────────────
// Calculates detection evaluation metrics using ground-truth labels.
//
// Rules:
// - Only rows with non-empty label/ground_truth are evaluated.
// - Positive AI prediction: 'Likely cloud AI' | 'Possible local AI'
// - Negative AI prediction: 'Ordinary web' | 'Uncertain'
// - Positive Ground Truth: 'ai', 'cloud_ai', 'local_ai', 'shadow_ai', 'true', '1', 'positive'
// - Negative Ground Truth: 'ordinary', 'benign', 'not_ai', 'web', 'false', '0', 'negative'
// - Unlabeled rows are NOT quietly assumed to be true or false.
// - If denominator is 0, metric returns null (UI shows 'Pending labels').
// - If expected_provider is supplied, calculate provider match accuracy separately.

export interface EvaluableRow {
  classification: string;           // 'Likely cloud AI' | 'Possible local AI' | 'Ordinary web' | 'Uncertain'
  provider: string;                 // detected provider name
  ground_truth_label?: string | null;
  expected_provider?: string | null;
}

export interface MetricValue {
  value: number | null;            // 0.0 to 1.0, or null if denominator == 0
  formatted: string;               // e.g. '87.5%' or 'Pending labels'
  numerator: number;
  denominator: number;
}

export interface ProviderEval {
  totalWithExpected: number;
  matches: number;
  accuracy: MetricValue;
}

export interface DatasetEvaluationReport {
  totalRows: number;
  labeledRows: number;
  unlabeledRows: number;
  confusionMatrix: {
    truePositives: number;
    falsePositives: number;
    trueNegatives: number;
    falseNegatives: number;
  };
  metrics: {
    precision: MetricValue;
    recall: MetricValue;
    falsePositiveRate: MetricValue;
    accuracy: MetricValue;
  };
  providerEvaluation: ProviderEval;
  disclaimer: string;
}

/**
 * Normalizes ground-truth label string to boolean (true = AI, false = non-AI) or null if unknown/unlabeled.
 */
export function normalizeGroundTruth(label: string | null | undefined): boolean | null {
  if (!label) return null;
  const l = label.trim().toLowerCase();

  // Positive AI truth labels
  if (
    l === 'ai' ||
    l === 'cloud_ai' ||
    l === 'cloud-ai' ||
    l === 'local_ai' ||
    l === 'local-ai' ||
    l === 'shadow_ai' ||
    l === 'shadow-ai' ||
    l === 'true' ||
    l === '1' ||
    l === 'positive' ||
    l === 'malicious'
  ) {
    return true;
  }

  // Negative (non-AI / benign / ordinary) truth labels
  if (
    l === 'ordinary' ||
    l === 'benign' ||
    l === 'not_ai' ||
    l === 'not-ai' ||
    l === 'web' ||
    l === 'ordinary_web' ||
    l === 'false' ||
    l === '0' ||
    l === 'negative'
  ) {
    return false;
  }

  return null;
}

/**
 * Normalizes system detection into positive (AI) or negative (non-AI).
 */
export function isPredictedAsAi(classification: string): boolean {
  return classification === 'Likely cloud AI' || classification === 'Possible local AI';
}

function makeMetric(num: number, den: number): MetricValue {
  if (den === 0) {
    return {
      value: null,
      formatted: 'Pending labels',
      numerator: num,
      denominator: den,
    };
  }
  const ratio = num / den;
  return {
    value: ratio,
    formatted: `${(ratio * 100).toFixed(1)}%`,
    numerator: num,
    denominator: den,
  };
}

/**
 * Computes evaluation metrics over a collection of event rows.
 */
export function evaluateDataset(rows: EvaluableRow[]): DatasetEvaluationReport {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  let labeledCount = 0;

  let expectedCount = 0;
  let providerMatches = 0;

  for (const row of rows) {
    const truth = normalizeGroundTruth(row.ground_truth_label);

    if (truth !== null) {
      labeledCount++;
      const pred = isPredictedAsAi(row.classification);

      if (truth === true && pred === true) {
        tp++;
      } else if (truth === false && pred === true) {
        fp++;
      } else if (truth === false && pred === false) {
        tn++;
      } else if (truth === true && pred === false) {
        fn++;
      }
    }

    // Provider evaluation (only when expected_provider is given)
    if (row.expected_provider && row.expected_provider.trim() !== '') {
      expectedCount++;
      const expected = row.expected_provider.trim().toLowerCase();
      const detected = (row.provider || '').trim().toLowerCase();

      // Check match: e.g. 'openai' matches 'openai', 'ollama' matches 'ollama / local'
      if (
        detected === expected ||
        detected.includes(expected) ||
        expected.includes(detected)
      ) {
        providerMatches++;
      }
    }
  }

  const unlabeledCount = rows.length - labeledCount;

  // Precision = TP / (TP + FP)
  const precision = makeMetric(tp, tp + fp);

  // Recall (Sensitivity) = TP / (TP + FN)
  const recall = makeMetric(tp, tp + fn);

  // False Positive Rate = FP / (FP + TN)
  const falsePositiveRate = makeMetric(fp, fp + tn);

  // Accuracy = (TP + TN) / (TP + FP + TN + FN)
  const accuracy = makeMetric(tp + tn, tp + fp + tn + fn);

  const providerAccuracy = makeMetric(providerMatches, expectedCount);

  return {
    totalRows: rows.length,
    labeledRows: labeledCount,
    unlabeledRows: unlabeledCount,
    confusionMatrix: {
      truePositives: tp,
      falsePositives: fp,
      trueNegatives: tn,
      falseNegatives: fn,
    },
    metrics: {
      precision,
      recall,
      falsePositiveRate,
      accuracy,
    },
    providerEvaluation: {
      totalWithExpected: expectedCount,
      matches: providerMatches,
      accuracy: providerAccuracy,
    },
    disclaimer:
      'Evaluation metrics describe this specific imported/simulated test dataset, not real-world network accuracy. Calculations apply only to rows with explicit ground-truth labels.',
  };
}
