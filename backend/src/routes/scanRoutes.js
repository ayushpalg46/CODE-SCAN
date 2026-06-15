import { Router } from 'express';
import { startScan, getScanStatus, generateAiSolution, validateTargetEndpoint } from '../controllers/scanController.js';

const router = Router();

// Endpoint to trigger a new scan job
router.post('/start', startScan);

// Endpoint to poll status of an ongoing scan job
router.get('/status/:scanId', getScanStatus);

// Endpoint to generate AI solution for selected vulnerability
router.post('/ai-solution', generateAiSolution);

// Endpoint to validate if target exists on the internet
router.post('/validate', validateTargetEndpoint);

export { router as scanRouter };
