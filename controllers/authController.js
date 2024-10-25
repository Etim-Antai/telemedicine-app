const bcrypt = require('bcrypt');
const session = require('express-session');
const patientModel = require('../models/patientModel');

// User Login
exports.login = async (req, res) => {
    const { email, password } = req.body;

    try {
        // Check if the patient exists in the database
        const patient = await patientModel.findByEmail(email);
        
        if (!patient) {
            console.log('Login failed: No user found with email', email);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare provided password with stored password hash
        const isPasswordValid = await bcrypt.compare(password, patient.password_hash);

        if (!isPasswordValid) {
            console.log('Login failed: Incorrect password for email', email);
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Start user session
        req.session.userId = patient.id;
        console.log('Patient logged in:', { id: patient.id, email });

        res.status(200).json({ message: 'Login successful' });
    } catch (error) {
        console.error('Error during login:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

// User Logout
exports.logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Error during logout:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }
        console.log('Patient logged out:', req.session.userId);
        res.status(200).json({ message: 'Logout successful' });
    });
};
