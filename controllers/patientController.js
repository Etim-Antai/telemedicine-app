const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const db = require('../config/db'); // Your database configuration
const { body, validationResult } = require('express-validator');

const app = express();

// Middleware setup
app.use(cors()); // Enable CORS
app.use(express.json()); // Parse JSON request bodies

// Patient Registration
const register = async (req, res) => {
    // Validate input data
    await body('first_name').notEmpty().withMessage('First name is required').run(req);
    await body('last_name').notEmpty().withMessage('Last name is required').run(req);
    await body('email').isEmail().withMessage('Email is not valid').run(req);
    await body('password').isLength({ min: 10 }).withMessage('Password must be at least 10 characters long').run(req);
    await body('phone').notEmpty().withMessage('Phone number is required').run(req);
    await body('date_of_birth').notEmpty().withMessage('Date of birth is required').run(req);
    await body('gender').notEmpty().withMessage('Gender is required').run(req);
    await body('address').notEmpty().withMessage('Address is required').run(req);

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;

    try {
        console.log('Registration attempt:', req.body); // Log registration attempt

        // Check for duplicates
        const [duplicateResults] = await db.promise().query('SELECT * FROM patients WHERE email = ? OR phone = ?', [email, phone]);
        if (duplicateResults.length > 0) {
            console.log('Registration failed: Email or phone number already in use');
            return res.status(400).json({ message: 'Email or phone number already in use' });
        }

        // Hash the plain password
        const hashedPassword = await bcrypt.hash(password, 10);

        // SQL query to insert new patient
        const query = 'INSERT INTO patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await db.promise().query(query, [first_name, last_name, email, hashedPassword, phone, date_of_birth, gender, address]);


        //log new registration email and password
        console.log('New patient registered:', { email, password }); // Log new registration
        res.status(201).json({ message: 'Patient registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error.message || error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Patient Login
const login = async (req, res) => {
    const { email, password } = req.body;
    console.log('Login attempt:', req.body);

    try {
        const query = 'SELECT * FROM patients WHERE email = ?'; // Ensure the table name is correct
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

        // Start user session: Store user info in the session
        req.session.user = { // Change here to set user in session
            id: patient.patient_id,  
            email: patient.email,
            first_name: patient.first_name, // Include first name
            last_name: patient.last_name, // Include last name
            phone: patient.phone
        };

        console.log('Patient logged in:', { id: patient.patient_id, email });

        // Respond with the necessary data for local storage
        res.status(200).json({
            success: true,
            message: 'Login successful',
            email: patient.email,
            first_name: patient.first_name, // Include first name
            last_name: patient.last_name, // Include last name
            phone: patient.phone
        });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Get Patient Profile
const getProfile = async (req, res) => {
    const patientId = req.session.userId;

    if (!patientId) {
        return res.status(401).json({ message: 'Unauthorized access' });
    }

    console.log('Fetching profile for patient ID:', patientId); // Log fetching profile attempt

    try {
        const query = 'SELECT first_name, last_name, email, phone, date_of_birth, gender, address FROM patients WHERE patient_id = ?';
        const [results] = await db.promise().query(query, [patientId]);

        if (results.length === 0) {
            console.log('Profile fetch failed: No patient found with ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Profile fetched successfully for patient ID:', patientId);
        res.status(200).json(results[0]);
    } catch (error) {
        console.error('Error fetching patient profile:', error.message || error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Update Patient Profile
const updateProfile = async (req, res) => {
    const { first_name, last_name, phone, date_of_birth, gender, address } = req.body;
    const patientId = req.session.userId;

    if (!patientId) {
        return res.status(401).json({ message: 'Unauthorized access' });
    }

    console.log('Profile update attempt for patient ID:', patientId, 'with data:', req.body); // Log profile update attempt

    try {
        // Validate input data
        if (!first_name && !last_name && !phone && !date_of_birth && !gender && !address) {
            return res.status(400).json({ message: 'At least one field is required for update' });
        }

        // Build the update query dynamically
        const fields = [];
        const values = [];
        if (first_name) { fields.push('first_name = ?'); values.push(first_name); }
        if (last_name) { fields.push('last_name = ?'); values.push(last_name); }
        if (phone) { fields.push('phone = ?'); values.push(phone); }
        if (date_of_birth) { fields.push('date_of_birth = ?'); values.push(date_of_birth); }
        if (gender) { fields.push('gender = ?'); values.push(gender); }
        if (address) { fields.push('address = ?'); values.push(address); }

        // Add patient ID to values for the WHERE clause
        values.push(patientId);

        const query = `UPDATE Patients SET ${fields.join(', ')} WHERE patient_id = ?`;
        const [results] = await db.promise().query(query, values);

        if (results.affectedRows === 0) {
            console.log('Profile update failed: No rows affected for patient ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Patient profile updated:', { id: patientId });
        res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating patient profile:', error.message || error);
        res.status(500).json({ message: 'Error updating profile' });
    }
};




// Export the controller functions
module.exports = {
    register,
    login,
    getProfile,
    updateProfile
};
