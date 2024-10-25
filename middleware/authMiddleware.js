// middleware/authMiddleware.js

const isAuthenticated = (req, res, next) => {
    // Check if the user is authenticated by verifying the session
    if (req.session && req.session.userId) {
        console.log('User is authenticated. User ID:', req.session.userId); // Log successful authentication
        return next(); // User is authenticated, proceed to the next middleware or route handler
    } else {
        console.log('User is not authenticated. Request URL:', req.originalUrl); // Log if user is not authenticated
        return res.status(401).json({ message: 'Unauthorized: Please log in to access this resource' }); // Return unauthorized error
    }
};

module.exports = isAuthenticated;
