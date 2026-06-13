import crypto from 'crypto';
import { spawn } from 'child_process';
import path from 'path';

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
  job.progress = 15;
  scanStore.set(scanId, job);

  const scriptPath = path.join(process.cwd(), 'scanners', 'scanner_bridge.py');

  try {
    const pythonProcess = spawn('python', [
      scriptPath,
      '--type', targetType,
      '--target', targetValue,
      '--mode', scanMode
    ]);

    let stdoutData = '';
    let stderrData = '';

    pythonProcess.stdout.on('data', (data) => {
      stdoutData += data.toString();
      // Handle progress lines
      const lines = stdoutData.split('\n');
      for (const line of lines) {
        if (line.trim().startsWith('{"progress":')) {
          try {
            const parsed = JSON.parse(line.trim());
            if (parsed.progress !== undefined) {
              job.progress = parsed.progress;
              scanStore.set(scanId, job);
            }
          } catch (e) {
            // Ignore parse error
          }
        }
      }
    });

    pythonProcess.stderr.on('data', (data) => {
      stderrData += data.toString();
    });

    pythonProcess.on('close', (code) => {
      const updatedJob = scanStore.get(scanId);
      if (!updatedJob) return;

      updatedJob.completedAt = Date.now();

      if (code !== 0) {
        console.error(`Scanner process exited with code ${code}. Stderr: ${stderrData}`);
        updatedJob.status = 'failed';
        updatedJob.error = `Scanner process exited with code ${code}. Stderr: ${stderrData.substring(0, 500)}`;
        scanStore.set(scanId, updatedJob);
        return;
      }

      try {
        const jsonMatch = stdoutData.match(/\{[\s\S]*\}/g);
        if (!jsonMatch) {
          throw new Error('No valid JSON structure found in scanner output.');
        }
        const finalJsonStr = jsonMatch[jsonMatch.length - 1];
        const result = JSON.parse(finalJsonStr);

        const findings = result.findings || [];
        let rawScore = 0;
        const summary = { critical: 0, high: 0, medium: 0, low: 0 };

        for (const finding of findings) {
          const severity = (finding.severity || 'low').toLowerCase();
          if (severity === 'critical') {
            rawScore += 40;
            summary.critical++;
          } else if (severity === 'high') {
            rawScore += 20;
            summary.high++;
          } else if (severity === 'medium') {
            rawScore += 10;
            summary.medium++;
          } else {
            rawScore += 5;
            summary.low++;
          }
        }

        const score = 100 - Math.min(rawScore, 100);

        updatedJob.status = 'completed';
        updatedJob.progress = 100;
        updatedJob.results = {
          findings,
          score,
          summary
        };
      } catch (err) {
        console.error('Failed to parse scanner output JSON:', err, 'Stdout:', stdoutData);
        updatedJob.status = 'failed';
        updatedJob.error = `Invalid scanner output: ${err.message}`;
      }

      scanStore.set(scanId, updatedJob);
    });

  } catch (err) {
    console.error('Error spawning scanner process:', err);
    job.status = 'failed';
    job.error = `Failed to start scanner process: ${err.message}`;
    job.completedAt = Date.now();
    scanStore.set(scanId, job);
  }
};
