const express = require('express');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');
const db = require('../config/db'); // Your database configuration
const verifyToken = require('../middleware/auth'); // Import the token verification middleware

const router = express.Router();

// Patient Registration
router.post('/register', [
    body('first_name').notEmpty().withMessage('First name is required'),
    body('last_name').notEmpty().withMessage('Last name is required'),
    body('email').isEmail().withMessage('Must be a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('phone').notEmpty().withMessage('Phone number is required'),
    body('gender').notEmpty().withMessage('Gender is required'),
    body('address').notEmpty().withMessage('Address is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;

    try {
        console.log('Registration attempt:', req.body);

        // Check for duplicates
        const [duplicateResults] = await db.query('SELECT * FROM patients WHERE email = ? OR phone = ?', [email, phone]);
        if (duplicateResults.length > 0) {
            console.log('Registration failed: Email or phone number already in use');
            return res.status(400).json({ message: 'Email or phone number already in use' });
        }

        // Hash the plain password
        const hashedPassword = await bcrypt.hash(password, 12);

        // SQL query to insert new patient
        const query = 'INSERT INTO patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await db.query(query, [first_name, last_name, email, hashedPassword, phone, date_of_birth, gender, address]);

        console.log('New patient registered:', { email });
        res.status(201).json({ message: 'Patient registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Patient Login
router.post('/login', [
    body('email').isEmail().withMessage('Must be a valid email'),
    body('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    console.log('Login attempt:', req.body);

    try {
        const query = 'SELECT * FROM patients WHERE email = ?';
        const [results] = await db.query(query, [email]);

        if (results.length === 0) {
            console.log('Login failed: No user found with email', email);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const patient = results[0]; // Get the first result
        const isPasswordValid = await bcrypt.compare(password, patient.password_hash);

        if (!isPasswordValid) {
            console.log('Login failed: Incorrect password for email', email);
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Generate a JWT token
        const token = jwt.sign({
            id: patient.id,
            email: patient.email,
            first_name: patient.first_name,
            last_name: patient.last_name,
            phone: patient.phone
        }, process.env.JWT_SECRET, { expiresIn: "1h" }); // Token expires in 1 hour

        console.log('Patient logged in:', { id: patient.id, email });

        // Include token in the response
        res.status(200).json({
            success: true,
            message: 'Login successful',
            token, // Send the token back to the client
            email: patient.email,
            first_name: patient.first_name, // Include first name
            last_name: patient.last_name, // Include last name
            phone: patient.phone
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Get Patient Profile
router.get('/profile', verifyToken, async (req, res) => {
    const patientId = req.user.id; // Get patient ID from decoded token

    console.log('Fetching profile for patient ID:', patientId);

    try {
        const query = 'SELECT first_name, last_name, email, phone, date_of_birth, gender, address FROM patients WHERE id = ?';
        const [results] = await db.query(query, [patientId]);

        if (results.length === 0) {
            console.log('Profile fetch failed: No patient found with ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Profile fetched successfully for patient ID:', patientId);
        res.status(200).json(results[0]);
    } catch (error) {
        console.error('Error fetching patient profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Update Patient Profile
router.put('/profile', [
    body('first_name').optional().notEmpty().withMessage('First name cannot be empty'),
    body('last_name').optional().notEmpty().withMessage('Last name cannot be empty'),
    body('phone').optional().isMobilePhone('any').withMessage('Must be a valid phone number'),
    body('date_of_birth').optional().isDate().withMessage('Must be a valid date'),
    body('gender').optional().notEmpty().withMessage('Gender cannot be empty'),
    body('address').optional().notEmpty().withMessage('Address cannot be empty'),
], verifyToken, async (req, res) => {
    const patientId = req.user.id; // Get patient ID from decoded token

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { first_name, last_name, phone, date_of_birth, gender, address } = req.body;

    console.log('Profile update attempt for patient ID:', patientId);

    try {
        const query = 'UPDATE patients SET first_name = ?, last_name = ?, phone = ?, date_of_birth = ?, gender = ?, address = ? WHERE id = ?';
        const values = [first_name || null, last_name || null, phone || null, date_of_birth || null, gender || null, address || null, patientId];

        const [results] = await db.query(query, values);
        if (results.affectedRows === 0) {
            console.log('Profile update failed: No rows affected for patient ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Patient profile updated:', { id: patientId });
        res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating patient profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Export the router
module.exports = router;
