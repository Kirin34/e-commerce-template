const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const dotenv = require('dotenv');
const winston = require('winston');

// Load .env file
dotenv.config({ path: path.join(__dirname, '.env') });

// Configure logger
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
  ],
});

if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple(),
  }));
}

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Middleware for authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    logger.warn('Authentication failed: No token provided');
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn('Authentication failed: Invalid token', { error: err.message });
      return res.sendStatus(403);
    }
    req.user = user;
    next();
  });
};

// Database connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/myshop', {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    logger.info('MongoDB connected successfully');
  } catch (error) {
    logger.error('MongoDB connection error:', { error: error.message });
    process.exit(1);
  }
};

// User model
const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true, minlength: 60 },
  createdAt: { type: Date, default: Date.now },
});

const User = mongoose.model('User', UserSchema);


// Routes

// Registration route
app.post('/users', async (req, res) => {
  try {
    const { username, password, email } = req.body;
    logger.info('User registration attempt', { username, email });
    
    if (!username || !password || !email) {
      logger.warn('Registration failed: Missing required fields');
      return res.status(400).json({ error: 'Username, password, and email are required' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();
    
    logger.info('User registered successfully', { username, email });
    res.status(201).json({ message: 'User created successfully', userId: newUser._id });
  } catch (error) {
    if (error.code === 11000) {
      logger.warn('Registration failed: Duplicate username or email', { error: error.message });
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    logger.error('Registration error', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Login route
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    logger.info('Login attempt', { username });

    const user = await User.findOne({ $or: [{ username }, { email: username }] });
    if (!user) {
      logger.warn('Login failed: User not found', { username });
      return res.status(400).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logger.warn('Login failed: Invalid credentials', { username });
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    logger.info('Login successful', { username });
    res.json({ message: 'Login successful', token });
  } catch (error) {
    logger.error('Login error', { error: error.message });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all users route
app.get('/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({}, '-password');
    logger.info('Retrieved all users', { userId: req.user.userId });
    res.json(users);
  } catch (error) {
    logger.error('Error fetching users', { error: error.message, userId: req.user.userId });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update password route
app.put('/users/password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userEmail = req.user.email; // Get email from the authenticated token

    logger.info('Password update attempt', { email: userEmail });

    if (!currentPassword || !newPassword) {
      logger.warn('Password update failed: Missing required fields', { email: userEmail });
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    const user = await User.findOne({ email: userEmail });
    if (!user) {
      logger.warn('Password update failed: User not found', { email: userEmail });
      return res.status(404).json({ error: 'User not found' });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      logger.warn('Password update failed: Incorrect current password', { email: userEmail });
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    // Password strength check (example: at least 8 characters)
    if (newPassword.length < 8) {
      logger.warn('Password update failed: New password too weak', { email: userEmail });
      return res.status(400).json({ error: 'New password must be at least 8 characters long' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    logger.info('Password updated successfully', { email: userEmail });
    res.json({ message: 'Password updated successfully' });
  } catch (error) {
    logger.error('Error updating password', { error: error.message, email: req.user.email });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete user route
app.delete('/users', authenticateToken, async (req, res) => {
  try {
    const userEmail = req.user.email;
    logger.info('User deletion attempt', { email: userEmail });

    const user = await User.findOne({ email: userEmail });
    if (!user) {
      logger.warn('User deletion failed: User not found', { email: userEmail });
      return res.status(404).json({ error: 'User not found' });
    }

    await User.findByIdAndDelete(user._id);
    logger.info('User deleted successfully', { email: userEmail });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    logger.error('Error deleting user', { error: error.message, email: req.user.email });
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Server startup
const PORT = process.env.PORT || 3000;

connectDB().then(() => {
  app.listen(PORT, () => logger.info(`Server running on port ${PORT}`));
});

// Error handling for unhandled promise rejections
process.on('unhandledRejection', (error) => {
  logger.error('Unhandled Rejection', { error: error.message });
  process.exit(1);
});