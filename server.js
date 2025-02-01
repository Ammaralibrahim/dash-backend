const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const User = require('./models/User'); 
const jwt = require('jsonwebtoken'); 
const dotenv = require('dotenv'); // To load environment variables

dotenv.config(); // Load environment variables from .env file

const app = express();
const PORT = process.env.PORT || 5000;

mongoose.connect(process.env.MONGO_URI, { 
    useNewUrlParser: true, 
    useUnifiedTopology: true 
  })
    .then(() => console.log('MongoDB connected successfully'))
    .catch(err => console.log('MongoDB connection error:', err));
  

    app.use(cors({
      origin: 'https://brightedu-admin.vercel.app', // Yalnızca bu frontend domain'ine izin ver
      methods: ['GET', 'POST'], // Yalnızca GET ve POST isteklerine izin ver
      allowedHeaders: ['Content-Type', 'Authorization'], // Content-Type ve Authorization başlıklarına izin ver
      credentials: true, // Çerezler veya oturum verileri ile istek yapılacaksa
    }));
      
      app.use(express.json());

// JWT Secret Key should be in the environment variable
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret';

// Registration endpoint
app.post('/register', [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
    body('confirmPassword').custom((value, { req }) => {
        if (value !== req.body.password) {
          throw new Error('Passwords do not match');
        }
        return true;
      }),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'Email is already registered' });
    }

    try {
      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = new User({
        email,
        password: hashedPassword,
      });

      await newUser.save();
      return res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
      return res.status(500).json({ message: 'Internal Server Error' });
    }
  });

// Login endpoint
app.post('/login', [
    body('email').isEmail().withMessage('Please enter a valid email'),
    body('password').exists().withMessage('Password is required'),
  ], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { email, password } = req.body;

    try {
      const user = await User.findOne({ email });
      if (!user) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return res.status(400).json({ message: 'Invalid email or password' });
      }

      const token = jwt.sign(
        { userId: user._id, email: user.email },
        JWT_SECRET, // Secret key
        { expiresIn: '1h' }
      );

      return res.status(200).json({
        message: 'Login successful',
        token,
      });

    } catch (error) {
      return res.status(500).json({ message: 'Internal Server Error' });
    }
  });

// Middleware to verify JWT token and get user data
app.get('/user', async (req, res) => {
    const token = req.headers['authorization']?.split(' ')[1]; // Bearer token formatında olmalı
  
    if (!token) {
      return res.status(401).json({ message: 'No token provided' });
    }
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET); // Token'ı decode et
      const userId = decoded.userId; // Kullanıcının id'si
      const user = await User.findById(userId); // Kullanıcıyı bul
  
      if (!user) {
        return res.status(404).json({ message: 'User not found' });
      }
  
      return res.status(200).json({
        email: user.email,
        // İhtiyaç duyulacak diğer kullanıcı verilerini ekleyebilirsiniz
      });
    } catch (error) {
      return res.status(401).json({ message: 'Invalid or expired token' });
    }
  });
  

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
