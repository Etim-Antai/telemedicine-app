const db = require('../config/db');

// Function to create a patient in the database
exports.createPatient = async (data) => {
    const { first_name, last_name, email, password_hash, phone, date_of_birth, gender, address } = data;

    if (!first_name || !last_name || !email || !password_hash || !phone || !date_of_birth || !gender || !address) {
        throw new Error('All fields are required');
    }

    try {
        const query = `
            INSERT INTO Patients (first_name, last_name, email, password_hash, phone, date_of_birth, gender, address) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `;
        const [result] = await db.promise().query(query, [first_name, last_name, email, password_hash, phone, date_of_birth, gender, address]);

        return result.insertId; // Return the ID of the newly created patient
    } catch (error) {
        console.error('Error creating patient:', error.message);
        throw new Error('Database operation failed');
    }
};

// Function to get a patient by ID
exports.getPatientById = async (id) => {
    if (!id) {
        throw new Error('Patient ID is required');
    }

    try {
        const query = 'SELECT * FROM Patients WHERE patient_id = ?';
        const [results] = await db.promise().query(query, [id]);

        if (results.length === 0) {
            throw new Error('Patient not found');
        }

        return results[0]; // Return the patient data
    } catch (error) {
        console.error('Error fetching patient by ID:', error.message);
        throw new Error('Database operation failed');
    }
};

// Add more patient-related database functions as needed
