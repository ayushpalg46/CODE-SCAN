import crypto from 'crypto';

// In-memory job state store
const scanStore = new Map();

// TTL manager: Prune finished/failed jobs older than 10 minutes from memory every minute
const JOB_TTL_MS = 10 * 60 * 1000;
setInterval(() => {
  const now = Date.now();
  for (const [scanId, job] of scanStore.entries()) {
    if (now - job.createdAt > JOB_TTL_MS) {
      scanStore.delete(scanId);
    }
  }
}, 60000);

/**
 * Triggers a new scan execution.
 * Body options:
 * - targetType: 'url' | 'github'
 * - targetValue: string
 * - scanMode: 'basic' | 'medium' | 'advanced'
 */
export const startScan = async (req, res) => {
  try {
    const { targetType, targetValue, scanMode } = req.body;

    // Simple validation validation
    if (!targetType || !targetValue || !scanMode) {
      return res.status(400).json({ error: 'Missing targetType, targetValue, or scanMode in request.' });
    }

    if (!['basic', 'medium', 'advanced'].includes(scanMode)) {
      return res.status(400).json({ error: 'scanMode must be one of: basic, medium, advanced.' });
    }

    if (!['url', 'github'].includes(targetType)) {
      return res.status(400).json({ error: 'targetType must be one of: url, github.' });
    }

    const scanId = crypto.randomUUID();

    // Set up default state
    const jobState = {
      scanId,
      targetType,
      targetValue,
      scanMode,
      status: 'pending',
      progress: 0,
      results: null,
      error: null,
      createdAt: Date.now(),
      completedAt: null
    };

    scanStore.set(scanId, jobState);

    // Asynchronously begin scanner execution (mock for initial scaffolding)
    runScanSubprocess(scanId, targetType, targetValue, scanMode);

    return res.status(202).json({
      message: 'Scan job accepted.',
      scanId,
      status: 'pending'
    });
  } catch (err) {
    console.error('Error triggering scan:', err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
};

/**
 * Polls the current status of an ongoing scan job.
 */
export const getScanStatus = (req, res) => {
  const { scanId } = req.params;
  const job = scanStore.get(scanId);

  if (!job) {
    return res.status(404).json({ error: 'Scan job not found or expired.' });
  }

  return res.json(job);
};

/**
 * Mock async execution simulation for Basic, Medium, and Advanced scanning modes.
 */
const runScanSubprocess = async (scanId, targetType, targetValue, scanMode) => {
  const job = scanStore.get(scanId);
  if (!job) return;

  job.status = 'running';
  job.progress = 10;

  try {
    // Basic Mode: Normal common vulnerability tests (low-medium level findings)
    if (scanMode === 'basic') {
      await simulateDelay(2000);
      job.progress = 50;
      await simulateDelay(2000);
      job.progress = 100;
      job.status = 'completed';
      job.results = {
        findings: [
          { module: 'Headers', severity: 'low', description: 'Missing X-Frame-Options security header.' }
        ]
      };
    } 
    // Medium Mode: Intermediate scan tests (medium-high level findings)
    else if (scanMode === 'medium') {
      await simulateDelay(3000);
      job.progress = 40;
      await simulateDelay(3000);
      job.progress = 100;
      job.status = 'completed';
      job.results = {
        findings: [
          { module: 'Dependencies', severity: 'medium', description: 'Outdated library path-to-regexp (CVE-2024-43796).' }
        ]
      };
    } 
    // Advanced Mode: Deep code/structural tests (high-critical level findings)
    else if (scanMode === 'advanced') {
      await simulateDelay(4000);
      job.progress = 30;
      await simulateDelay(4000);
      job.progress = 100;
      job.status = 'completed';
      job.results = {
        findings: [
          { module: 'InputValidation', severity: 'high', description: 'Reflected payload observed in DOM.' }
        ]
      };
    }

    job.completedAt = Date.now();
    scanStore.set(scanId, job);
  } catch (err) {
    job.status = 'failed';
    job.error = err.message;
    job.completedAt = Date.now();
    scanStore.set(scanId, job);
  }
};

const simulateDelay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
