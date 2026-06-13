import { Router } from 'express';
import { startScan, getScanStatus } from '../controllers/scanController.js';

const router = Router();

// Endpoint to trigger a new scan job
router.post('/start', startScan);

// Endpoint to poll status of an ongoing scan job
router.get('/status/:scanId', getScanStatus);

export { router as scanRouter };
