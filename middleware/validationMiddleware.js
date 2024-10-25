const session = require('express-session');

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    if (req.session && req.session.userId) { // Check for userId in the session
        return next(); // User is authenticated
    } else {
        return res.status(401).json({ message: 'Unauthorized: Please log in to access this resource' });
    }
}

// Middleware to check if the user is an admin
function isAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') {
        return next(); // User is an admin
    } else {
        return res.status(403).json({ message: 'Forbidden: Admins only' });
    }
}

module.exports = {
    isAuthenticated,
    isAdmin
};
