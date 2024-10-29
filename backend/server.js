const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const fs = require('fs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { query, body, validationResult } = require('express-validator');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET_KEY = process.env.SECRET_KEY;

app.use(cors({
    origin: ['http://localhost:3000'], // Only allow trusted domains
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
}));

app.use(bodyParser.json());
app.use(helmet()); // Secure headers

// Rate limiting to prevent brute force attacks
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per window
    message: "Too many requests, please try again later."
});

app.use('/api/', apiLimiter); // Apply rate limiter to all API routes

// Read users from users.json
const getUsers = () => {
    const data = fs.readFileSync('./users.json');
    return JSON.parse(data);
};

// Write users to users.json
const saveUser = (users) => {
    fs.writeFileSync('./users.json', JSON.stringify(users, null, 2));
};

// User signup with improved validation
app.post('/api/signup', [
    body('username').notEmpty().isString().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 8 })
], (req, res) => {
    const { username, email, password } = req.body;
    const users = getUsers();

    // Check validation result
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Check if user already exists
    const existingUser = users.find(u => u.username === username);
    if (existingUser) {
        return res.status(400).send('User already exists');
    }

    // Create new user with higher bcrypt salt rounds
    const newUser = { username, email, password: bcrypt.hashSync(password, 12) };
    users.push(newUser);
    saveUser(users);

    res.status(201).send('User registered successfully');
});

// User login with validation and secure token
app.post('/api/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').notEmpty()
], (req, res) => {
    const { email, password } = req.body;
    const users = getUsers();

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const user = users.find(u => u.email === email);
    if (!user) {
        return res.status(401).send('User not found');
    }

    // Check password
    const isValidPassword = bcrypt.compareSync(password, user.password);
    if (!isValidPassword) {
        return res.status(401).send('Invalid password');
    }

    // Create JWT token
    const token = jwt.sign({ email }, SECRET_KEY, { expiresIn: '15m' }); // Set token expiration to 15 minutes
    res.json({ token });
});

// Middleware to authenticate token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.sendStatus(401);
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Pagination and search for users
app.get('/api/users', authenticateToken, [
    query('page').optional().isInt({ min: 1 }).withMessage('Page must be a positive integer.'),
    query('limit').optional().isInt({ min: 1 }).withMessage('Limit must be a positive integer.'),
    query('search').optional().isString().withMessage('Search must be a string.')
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const users = getUsers();
    const { page = 1, limit = 12, search = '' } = req.query;

    // Filter users based on the search term (case insensitive)
    const filteredUsers = users.filter(user =>
        user.username.toLowerCase().includes(search.toLowerCase()) ||
        user.email.toLowerCase().includes(search.toLowerCase())
    );

    const total = filteredUsers.length;
    const startIndex = (page - 1) * limit;
    const endIndex = startIndex + parseInt(limit);
    const results = filteredUsers.slice(startIndex, endIndex);

    res.json({
        total,
        page: parseInt(page),
        limit: parseInt(limit),
        users: results,
    });
});

// Update user route
// Update user route
app.put('/api/users/:username', authenticateToken, [
    body('email').optional().isEmail().normalizeEmail(),
    body('password').optional().isLength({ min: 8 })
], (req, res) => {
    const { username } = req.params; // Get the username from the URL
    const { email } = req.body; // Get the new data from the request body
    const users = getUsers(); // Read existing users

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Find the user to update
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex === -1) {
        return res.status(404).send('User not found');
    }

    // Update user details
    if (email) {
        users[userIndex].email = email; // Update email
    }

    try {
        saveUser(users); // Save updated users back to JSON file
        res.status(200).send({ username, email: users[userIndex].email }); // Return updated user details
    } catch (err) {
        console.error('Failed to save user:', err);
        res.status(500).send('Failed to update user. Please try again later.');
    }
});

// Delete user route
app.delete('/api/users/:username', authenticateToken, (req, res) => {
    const { username } = req.params; // Get the username from the URL
    const users = getUsers(); // Read existing users

    // Find the user to delete
    const userIndex = users.findIndex(u => u.username === username);
    if (userIndex === -1) {
        return res.status(404).send('User not found');
    }

    // Remove the user from the array
    users.splice(userIndex, 1);

    try {
        saveUser(users); // Save updated users back to JSON file
        res.status(200).send({ message: 'User deleted successfully' }); // Return confirmation message
    } catch (err) {
        console.error('Failed to save users:', err);
        res.status(500).send('Failed to delete user. Please try again later.');
    }
});


// Protected route example
app.get('/api/protected', authenticateToken, (req, res) => {
    res.json({ message: 'This is a protected route', user: req.user });
});

// Global error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something went wrong!');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
