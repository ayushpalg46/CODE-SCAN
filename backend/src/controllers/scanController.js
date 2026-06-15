import crypto from 'crypto';
import { spawn } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns';
import { promisify } from 'util';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const lookupDns = promisify(dns.lookup);

// Asynchronously verifies if a website URL or GitHub repository actually exists and is reachable
const validateTarget = async (targetType, targetValue) => {
  if (targetType === 'url') {
    let urlString = targetValue.trim();
    if (!urlString.startsWith('http://') && !urlString.startsWith('https://')) {
      urlString = 'https://' + urlString;
    }

    let parsedUrl;
    try {
      parsedUrl = new URL(urlString);
    } catch (e) {
      throw new Error('Invalid website URL format.');
    }

    const hostname = parsedUrl.hostname;
    if (!hostname) {
      throw new Error('Invalid hostname in URL.');
    }

    // Bypass DNS resolve for localhost or local IPs to ease offline testing
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.')
    ) {
      return urlString;
    }

    // Resolve DNS to verify domain exists
    try {
      await lookupDns(hostname);
    } catch (e) {
      throw new Error(`The website domain '${hostname}' does not exist or has no DNS record.`);
    }

    // Verify HTTP connectivity
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      await fetch(urlString, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (CODE-SCAN Validator)' }
      });
      clearTimeout(timeoutId);
    } catch (e) {
      const isSslError =
        e.code === 'CERT_HAS_EXPIRED' ||
        e.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' ||
        e.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
        e.message?.includes('reason:') ||
        e.message?.includes('SSL');

      if (!isSslError) {
        throw new Error(`Failed to connect to '${urlString}'. The website might be offline or unreachable.`);
      }
    }

    return urlString;
  } else if (targetType === 'github') {
    let repoUrl = targetValue.trim();
    if (!repoUrl.startsWith('http://') && !repoUrl.startsWith('https://')) {
      repoUrl = 'https://' + repoUrl;
    }

    // Match public github owner/repo
    const githubRegex = /^https?:\/\/(www\.)?github\.com\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+\/?$/;
    if (!githubRegex.test(repoUrl)) {
      throw new Error('Invalid GitHub repository link format. Must be of the form: https://github.com/owner/repository');
    }

    // Verify GitHub repository is public and accessible
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 4000);
      const res = await fetch(repoUrl, {
        method: 'GET',
        signal: controller.signal,
        headers: { 'User-Agent': 'Mozilla/5.0 (CODE-SCAN Validator)' }
      });
      clearTimeout(timeoutId);
      if (res.status === 404) {
        throw new Error('The GitHub repository does not exist or is private.');
      } else if (res.status !== 200) {
        throw new Error(`GitHub returned status code ${res.status} for this repository.`);
      }
    } catch (e) {
      if (e.message.includes('does not exist') || e.message.includes('status code')) {
        throw e;
      }
      throw new Error('Failed to connect to GitHub to verify the repository.');
    }

    return repoUrl;
  }
};

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
 * - scanMode: 'basic' | 'modrate' | 'advanced'
 */
export const startScan = async (req, res) => {
  try {
    const { targetType, targetValue, scanMode } = req.body;

    // Simple validation validation
    if (!targetType || !targetValue || !scanMode) {
      return res.status(400).json({ error: 'Missing targetType, targetValue, or scanMode in request.' });
    }

    if (!['basic', 'modrate', 'advanced'].includes(scanMode)) {
      return res.status(400).json({ error: 'scanMode must be one of: basic, modrate, advanced.' });
    }

    if (!['url', 'github'].includes(targetType)) {
      return res.status(400).json({ error: 'targetType must be one of: url, github.' });
    }

    // Asynchronously perform real-world existance and reachability validation
    let validatedTargetValue;
    try {
      validatedTargetValue = await validateTarget(targetType, targetValue);
    } catch (err) {
      return res.status(400).json({ error: err.message });
    }

    const scanId = crypto.randomUUID();

    // Set up default state
    const jobState = {
      scanId,
      targetType,
      targetValue: validatedTargetValue,
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
    runScanSubprocess(scanId, targetType, validatedTargetValue, scanMode);

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
 * Categorizes a scan finding into one of the three dimensions: security, performance, or quality.
 */
const getCategoryForFinding = (finding) => {
  const id = (finding.id || '').toUpperCase();
  const title = (finding.title || '').toLowerCase();

  // Security Keywords
  if (
    id.includes('CREDENTIALS') ||
    id.includes('SECRET') ||
    id.includes('KEY_EXPOSED') ||
    id.includes('XSS') ||
    id.includes('SQL_INJECTION') ||
    id.includes('CSRF') ||
    id.includes('SSRF') ||
    id.includes('XXE') ||
    id.includes('CORS') ||
    id.includes('REDIRECT') ||
    id.includes('UNSECURED_') ||
    id.includes('UNAUTHENTICATED') ||
    id.includes('INSECURE') ||
    title.includes('password') ||
    title.includes('token') ||
    title.includes('key')
  ) {
    return 'security';
  }

  // Performance Keywords
  if (
    id.includes('TRANSPORT') ||
    id.includes('REDIRECT_MISSING') ||
    id.includes('PORT_EXPOSED') ||
    id.includes('PORT') ||
    id.includes('LEGACY') ||
    title.includes('port') ||
    title.includes('http') ||
    title.includes('protocol') ||
    title.includes('transport')
  ) {
    return 'performance';
  }

  // Quality Keywords (Default)
  return 'quality';
};

/**
 * Mock async execution simulation for Basic, Modrate, and Advanced scanning modes.
 */
const runScanSubprocess = async (scanId, targetType, targetValue, scanMode) => {
  const job = scanStore.get(scanId);
  if (!job) return;

  job.status = 'running';
  job.progress = 15;
  scanStore.set(scanId, job);

  const scriptPath = path.resolve(__dirname, '..', '..', '..', 'scanners', 'scanner_bridge.py');

  try {
    const pythonProcess = spawn('python', [
      '-u',
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

      let parsedResult = null;
      let parseError = null;
      try {
        const lines = stdoutData.split('\n');
        const nonProgressLines = lines.filter(line => !line.trim().startsWith('{"progress":'));
        const finalJsonStr = nonProgressLines.join('\n').trim();
        if (finalJsonStr) {
          parsedResult = JSON.parse(finalJsonStr);
        }
      } catch (err) {
        parseError = err;
      }

      if (parsedResult && (parsedResult.status === 'error' || parsedResult.error)) {
        updatedJob.status = 'failed';
        updatedJob.error = parsedResult.error || 'Scan failed.';
        scanStore.set(scanId, updatedJob);
        return;
      }

      if (code !== 0) {
        console.error(`Scanner process exited with code ${code}. Stderr: ${stderrData}`);
        updatedJob.status = 'failed';
        updatedJob.error = parsedResult?.error || `Scanner process exited with code ${code}. Stderr: ${stderrData.substring(0, 500)}`;
        scanStore.set(scanId, updatedJob);
        return;
      }

      try {
        if (!parsedResult) {
          throw parseError || new Error('No valid JSON structure found in scanner output.');
        }
        const result = parsedResult;

        const findings = result.findings || [];
        const summary = { critical: 0, high: 0, medium: 0, low: 0 };
        
        for (const finding of findings) {
          const severity = (finding.severity || 'low').toLowerCase();
          
          if (severity === 'critical') summary.critical++;
          else if (severity === 'high') summary.high++;
          else if (severity === 'medium') summary.medium++;
          else summary.low++;
        }

        let securityScore, qualityScore, performanceScore, score;

        if (result.scores) {
          securityScore = result.scores.securityScore !== undefined ? result.scores.securityScore : 100;
          qualityScore = result.scores.qualityScore !== undefined ? result.scores.qualityScore : 100;
          performanceScore = result.scores.performanceScore !== undefined ? result.scores.performanceScore : 100;
          score = result.scores.totalScore !== undefined ? result.scores.totalScore : Math.round((securityScore + qualityScore + performanceScore) / 3);
        } else {
          // Fallback to deduction calculation
          let securityDeduction = 0;
          let qualityDeduction = 0;
          let performanceDeduction = 0;

          for (const finding of findings) {
            const severity = (finding.severity || 'low').toLowerCase();
            let deduction = 5;
            if (severity === 'critical') deduction = 40;
            else if (severity === 'high') deduction = 20;
            else if (severity === 'medium') deduction = 10;

            const category = getCategoryForFinding(finding);
            if (category === 'security') {
              securityDeduction += deduction;
            } else if (category === 'performance') {
              performanceDeduction += deduction;
            } else {
              qualityDeduction += deduction;
            }
          }

          securityScore = Math.max(0, 100 - securityDeduction);
          qualityScore = Math.max(0, 100 - qualityDeduction);
          performanceScore = Math.max(0, 100 - performanceDeduction);
          score = Math.round((securityScore + qualityScore + performanceScore) / 3);
        }

        updatedJob.status = 'completed';
        updatedJob.progress = 100;
        updatedJob.results = {
          findings,
          score,
          securityScore,
          qualityScore,
          performanceScore,
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

export const generateAiSolution = async (req, res) => {
  try {
    const { title, description, file } = req.body;
    if (!title) {
      return res.status(400).json({ error: 'Missing vulnerability title.' });
    }

    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('GEMINI_API_KEY environment variable is not set');
      return res.status(500).json({ error: 'AI remediation is currently unavailable (API key not configured).' });
    }
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`;

    const promptText = `You are an elite cyber security expert. Write a clear, concise remediation solution for the following vulnerability:
Title: ${title}
${description ? `Description: ${description}` : ''}
${file ? `File: ${file}` : ''}

Provide a direct, step-by-step remediation guide in plain text or simple markdown. Keep it action-oriented, under 120 words. Include a brief code snippet if helpful.`;

    const response = await fetch(geminiUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        contents: [{
          parts: [{
            text: promptText
          }]
        }]
      })
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Gemini API returned error status:', response.status, errorText);
      return res.status(502).json({ error: 'Gemini AI API request failed.' });
    }

    const data = await response.json();
    const solutionText = data.candidates?.[0]?.content?.parts?.[0]?.text;

    if (!solutionText) {
      return res.status(502).json({ error: 'No response content returned from Gemini AI.' });
    }

    return res.json({ solution: solutionText.trim() });
  } catch (error) {
    console.error('Error generating AI solution:', error);
    return res.status(500).json({ error: 'Internal Server Error while generating AI solution.' });
  }
};

export const validateTargetEndpoint = async (req, res) => {
  try {
    const { targetType, targetValue } = req.body;
    if (!targetType || !targetValue) {
      return res.status(400).json({ error: 'Missing targetType or targetValue.' });
    }
    const canonicalUrl = await validateTarget(targetType, targetValue);
    return res.json({ valid: true, canonicalUrl });
  } catch (err) {
    return res.status(400).json({ valid: false, error: err.message });
  }
};
