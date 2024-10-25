const express = require('express');
const app = express();
const session = require('express-session');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const db = require('./config/db'); // Database configuration
const { body, validationResult } = require('express-validator');
const dotenv = require('dotenv');
const { isAuthenticated, isAdmin } = require('./middleware/validationMiddleware'); // Updated middleware import
const cors = require('cors');
const morgan = require('morgan');

// Load environment variables from .env before anything else
dotenv.config();

const PORT = process.env.PORT || 3000;

// Middleware setup
app.use(cors({
    origin: '*', // Allow all origins
    credentials: true // Allow credentials (consider security implications)
}));



app.use(bodyParser.json());
app.use(morgan('combined')); // Logging HTTP requests
app.use(session({
    secret: process.env.SESSION_SECRET || '1234567890', // Use environment variable for security
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 60000, // Cookie expiration time in milliseconds
        secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
        httpOnly: true // Prevent JavaScript access to cookies
    }
}));

// Middleware for logging activities
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl}`);
    next();
});

// Centralized error handler middleware
app.use((err, req, res, next) => {
    if (res.headersSent) {
        return next(err);
    }
    console.error('Error occurred:', err); // Log error details
    res.status(err.status || 500).json({ message: 'An error occurred, please try again later.' });
});

// Check for duplicate email and phone
const checkDuplicate = async (req, res) => {
    const { email, phone } = req.body;
    console.log('Checking for duplicate email and phone:', { email, phone });

    try {
        const query = 'SELECT * FROM patients WHERE email = ? OR phone = ?';
        const [results] = await db.query(query, [email, phone]);
        const isDuplicate = results.length > 0;
        console.log('Duplicate check result:', { isDuplicate });
        res.json({ isDuplicate });
    } catch (error) {
        console.error('Error checking duplicates:', error);
        return res.status(500).json({ message: 'Internal server error' });
    }
};

// Patient Registration
const register = async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        console.log('Validation errors during registration:', errors.array());
        return res.status(400).json({ errors: errors.array() });
    }

    const { first_name, last_name, email, password, phone, date_of_birth, gender, address } = req.body;
    console.log('Registration attempt:', req.body);

    try {
        // Check for duplicates
        const [duplicateResults] = await db.query('SELECT * FROM patients WHERE email = ? OR phone = ?', [email, phone]);
        if (duplicateResults.length > 0) {
            console.log('Registration failed: Email or phone number already in use');
            return res.status(400).json({ message: 'Email or phone number already in use' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // SQL query to insert new patient
        const query = 'INSERT INTO patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
        await db.query(query, [first_name, last_name, email, hashedPassword, phone, date_of_birth, gender, address]);

        console.log('New patient registered:', { email });
        res.status(201).json({ message: 'Patient registered successfully' });
    } catch (error) {
        console.error('Error during registration:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


// Patient Login
const login = async (req, res) => {
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

        // Start user session
        req.session.userId = patient.patient_id; // Set userId to patient.patient_id
        console.log('Patient logged in:', { id: patient.patient_id, email });

        // Modify the response to include first and last names
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
        res.status(500).json({ success: false, message: 'Internal server error' });
    }
};

// Profile Retrieval (Protected route with authentication)
const getProfile = async (req, res) => {
    const patientId = req.session.userId;

    console.log('Profile retrieval attempt for patient ID:', patientId);

    try {
        const query = 'SELECT first_name, last_name, email, phone, date_of_birth, gender, address FROM patients WHERE patient_id = ?';
        const [results] = await db.query(query, [patientId]);

        if (results.length === 0) {
            console.log('Profile retrieval failed: No patient found with ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        const patientProfile = results[0]; // Get the first result
        console.log('Patient profile retrieved:', { id: patientId });
        
        res.status(200).json(patientProfile); // Send back the patient profile
    } catch (error) {
        console.error('Error retrieving patient profile:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Add the profile retrieval route
app.get('/api/profile', isAuthenticated, getProfile);










// Profile Update (Protected route with authentication)
const updateProfile = async (req, res) => {
    const { first_name, last_name, phone, date_of_birth, gender, address } = req.body;
    const patientId = req.session.userId;

    console.log('Profile update attempt for patient ID:', patientId, 'with data:', req.body);

    try {
        const query = 'UPDATE patients SET first_name = ?, last_name = ?, phone = ?, date_of_birth = ?, gender = ?, address = ? WHERE patient_id = ?';
        const values = [first_name, last_name, phone, date_of_birth, gender, address, patientId];

        const [results] = await db.query(query, values);
        if (results.affectedRows === 0) {
            console.log('Profile update failed: No rows affected for patient ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Patient profile updated:', { id: patientId });
        res.status(200).json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Error updating patient profile:', error);
        res.status(500).json({ message: 'Error updating profile' });
    }
};

// Patient Deletion
const deletePatient = async (req, res) => {
    const patientId = req.session.userId; // Assuming you want to delete the logged-in user's profile
    console.log('Delete patient attempt for patient ID:', patientId);

    try {
        const query = 'DELETE FROM patients WHERE patient_id = ?';
        const [results] = await db.query(query, [patientId]);

        if (results.affectedRows === 0) {
            console.log('Delete failed: No patient found with ID', patientId);
            return res.status(404).json({ message: 'Patient not found' });
        }

        console.log('Patient deleted:', { id: patientId });
        req.session.destroy(); // Destroy session after deletion
        res.status(200).json({ message: 'Patient deleted successfully' });
    } catch (error) {
        console.error('Error deleting patient:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// Routes
app.post('/api/register', [
    body('first_name').notEmpty().withMessage('First name is required'),
    body('last_name').notEmpty().withMessage('Last name is required'),
    body('email').isEmail().withMessage('Invalid email format'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('phone').notEmpty().withMessage('Phone number is required'),
    body('date_of_birth').notEmpty().withMessage('Date of birth is required'),
    body('gender').notEmpty().withMessage('Gender is required'),
    body('address').notEmpty().withMessage('Address is required')
], register);

app.post('/api/login', login);
app.put('/api/profile', isAuthenticated, updateProfile); 
app.delete('/api/delete', isAuthenticated, deletePatient);
app.post('/api/check-duplicate', checkDuplicate);

// Example of an admin-only route
app.get('/api/admin/data', isAuthenticated, isAdmin, (req, res) => {
    res.json({ message: 'This is admin data.' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
