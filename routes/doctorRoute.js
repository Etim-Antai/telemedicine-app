const express = require('express');
const router = express.Router();
const doctorController = require('../controllers/doctorController');

router.post('/add', doctorController.addDoctor);

// Add more doctor routes as needed

module.exports = router;
