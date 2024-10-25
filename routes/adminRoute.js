const express = require('express');
const router = express.Router();
const adminController = require('../controllers/adminController');

router.get('/appointments', adminController.viewAppointments);

// Add more admin routes as needed

module.exports = router;
