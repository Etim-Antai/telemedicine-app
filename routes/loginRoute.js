// Patient Login Route
router.post('/patients/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const [results] = await pool.promise().query('SELECT * FROM Patients WHERE email = ?', [email]);
        
        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        const patient = results[0];
        const match = await bcrypt.compare(password, patient.password_hash);

        if (!match) {
            return res.status(401).json({ message: 'Invalid email or password' });
        }

        req.session.patientId = patient.id; // Store patient ID in session
        res.json({ message: 'Login successful' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Database error' });
    }
});
