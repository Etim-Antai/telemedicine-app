// middleware/auth.js
const jwt = require('jsonwebtoken');

// Middleware to check token
const verifyToken = (req, res, next) => {
    // Get the token from the Authorization header
    const token = req.headers['authorization']?.split(' ')[1]; // Split to get the token part
    if (!token) return res.status(401).json({ message: 'Unauthorized access' }); // No token

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET || 'your_jwt_secret_key', (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' }); // Invalid token

        req.user = user; // Attach user info to the request for future reference
        next(); // Move to the next middleware or route handler
    });
};

module.exports = verifyToken; // Export the middleware
