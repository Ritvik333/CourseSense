const express = require('express');
const axios = require('axios');
const path = require('path');
const app = express();
const port = process.env.PORT || 3000;

// Environment variables
const apiGatewayId = process.env.API_GATEWAY_ID || '7194mzc1ci';
const awsRegion = process.env.AWS_REGION || 'us-east-1';
const apiBaseUrl = `https://${apiGatewayId}.execute-api.${awsRegion}.amazonaws.com/v1`;

// Middleware
app.use(express.json());
app.use(express.static('public'));
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', 'http://course-feedback-env.eba-qp9ammb2.us-east-1.elasticbeanstalk.com');
    res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    next();
});

// Serve the main UI for all routes
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

// Health check endpoint for Beanstalk
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Registration endpoint
app.post('/register', async (req, res) => {
    const { role, username, password } = req.body;

    if (!role || !username || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        const response = await axios.post(`${apiBaseUrl}/auth`, {
            action: 'register',
            email: username,
            password,
            role
        }, { headers: { 'Content-Type': 'application/json' }, timeout: 10000 });

        const result = response.data;
        res.json({ success: true, message: 'Registration successful. Please verify your email and login.' });
    } catch (error) {
        console.error('Registration error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({ success: false, message: error.response?.data?.body || 'Registration failed. Please try again.' });
    }
});

// Login endpoint
app.post('/login', async (req, res) => {
    const { role, username, password } = req.body;

    if (!role || !username || !password) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        console.log("Trying to login for:", username);
        const response = await axios.post(`${apiBaseUrl}/auth`, {
            action: 'login',
            email: username,
            password: password
        }, { 
            headers: { 'Content-Type': 'application/json' }, 
            timeout: 10000
        });

        console.log("Raw response:", response.data); // Log the entire response
        let result;
        if (response.data.body) {
            result = JSON.parse(response.data.body);
        } else if (response.data) {
            result = response.data; // Try parsing the data directly if body is missing
        } else {
            throw new Error('No response data received from API Gateway');
        }
        console.log("Parsed result:", result);

        if (result.message === 'New password required') {
            return res.status(401).json({ success: false, message: result.message, session: result.session, challenge: result.challenge });
        } else if (result.message === 'MFA required') {
            return res.status(401).json({ success: false, message: result.message, session: result.session });
        }

        res.json({ success: true, message: 'Login successful', role: result.role, sessionId: result.sessionId });
    } catch (error) {
        console.error('Login error details:', {
            message: error.message,
            response: error.response ? {
                status: error.response.status,
                data: error.response.data,
                headers: error.response.headers
            } : 'No response'
        });
        res.status(error.response?.status || 500).json({ 
            success: false, 
            message: error.response?.data?.body || error.message || 'Login failed. Please try again.' 
        });
    }
});

// Set new password endpoint
app.post('/set-new-password', async (req, res) => {
    const { username, new_password, session } = req.body;

    if (!username || !new_password || !session) {
        return res.status(400).json({ success: false, message: 'All fields are required' });
    }

    try {
        const response = await axios.post(`${apiBaseUrl}/auth`, {
            action: 'set_new_password',
            email: username,
            new_password,
            session
        }, { headers: { 'Content-Type': 'application/json' }, timeout: 10000 });

        const result = JSON.parse(response.data.body);
        localStorage.setItem('role', result.role);
        localStorage.setItem('username', username);
        res.json({ success: true, message: 'Password set successfully', role: result.role });
    } catch (error) {
        console.error('Set password error:', error.response?.data || error.message);
        res.status(error.response?.status || 500).json({ success: false, message: error.response?.data?.body || 'Failed to set password.' });
    }
});

// Logout endpoint
app.get('/logout', async (req, res) => {
    const sessionId = req.query.sessionId || req.body.sessionId; // Get sessionId from query or body
    if (sessionId) {
        try {
            console.log("Attempting logout with sessionId:", sessionId);
            const response = await axios.post(`${apiBaseUrl}/auth`, {
                action: 'logout',
                sessionId
            }, { headers: { 'Content-Type': 'application/json' }, timeout: 10000 });
            console.log("Logout response:", response.data);
            localStorage.removeItem('role');
            localStorage.removeItem('username');
            localStorage.removeItem('sessionId');
        } catch (error) {
            console.error('Logout error details:', {
                message: error.message,
                response: error.response ? {
                    status: error.response.status,
                    data: error.response.data,
                    headers: error.response.headers
                } : 'No response'
            });
        }
    } else {
        console.log("No sessionId provided for logout");
    }
    res.redirect('/login');
});

// Submit feedback endpoint
app.post('/submit', async (req, res) => {
    try {
        console.log('Submitting feedback:', req.body);
        const apiResponse = await axios.post(
            `${apiBaseUrl}/submit`,
            req.body,
            { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
        );
        res.json(apiResponse.data);
    } catch (error) {
        console.error('Submit error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to submit feedback', details: error.response?.data || error.message });
    }
});

// Query feedback endpoint
app.get('/query', async (req, res) => {
    try {
        const courseId = req.query.course || 'ALL';
        console.log(`Querying feedback for course: ${courseId}`);
        const apiResponse = await axios.get(
            `${apiBaseUrl}/query?course=${courseId}`,
            { headers: { 'Content-Type': 'application/json' }, timeout: 10000 }
        );
        res.json(apiResponse.data);
    } catch (error) {
        console.error('Query error:', error.response?.data || error.message);
        res.status(500).json({ error: 'Failed to query feedback', details: error.response?.data || error.message });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({ error: 'Internal server error', message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong' });
});

// 404 handler
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', 'index.html')));

// Start server
app.listen(port, () => {
    console.log(`🚀 Course Feedback App running on port ${port}`);
    console.log(`📊 Dashboard: http://localhost:${port}`);
    console.log(`🔗 API Gateway ID: ${apiGatewayId}`);
    console.log(`🌍 AWS Region: ${awsRegion}`);
});

module.exports = app;