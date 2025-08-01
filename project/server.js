const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const bcrypt = require('bcrypt');
const app = express();

// MongoDB connection
mongoose.connect('mongodb://localhost:27017/loginApp')
    .then(() => console.log('Connected to MongoDB'))
    .catch(err => console.error('MongoDB connection error:', err));

// Configure storage for profile photos
const profilePhotoStorage = multer.diskStorage({
    destination: './uploads/profiles/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const uploadProfilePhoto = multer({ 
    storage: profilePhotoStorage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Configure storage for certificates
const certificateStorage = multer.diskStorage({
    destination: './uploads/certificates/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const uploadCertificate = multer({ 
    storage: certificateStorage,
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// User Schema
const userSchema = new mongoose.Schema({
    username: { type: String, unique: true },
    password: String,
    email: { type: String, unique: true },
    name: String,
    fullName: String,
    year: String,
    phone: String,
    mobile: String,
    address: String,
    profilePhoto: { type: String, default: 'default-avatar.png' },
    socialLinks: {
        github: String,
        twitter: String,
        instagram: String,
        facebook: String
    },
    certificates: [{
        name: String,
        issuer: String,
        date: Date,
        description: String,
        fileUrl: String
    }],
    interests: [{
        name: String,
        icon: String
    }]
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Session configuration
app.use(session({
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 1 day
    }
}));

// Authentication middleware
const authenticateUser = (req, res, next) => {
    if (req.session.userId) {
        next();
    } else {
        res.status(401).json({ error: 'Not authenticated' });
    }
};

// Routes

// Register new user
app.post('/register', async (req, res) => {
    try {
        // Check if username or email already exists
        const existingUser = await User.findOne({ 
            $or: [
                { username: req.body.username },
                { email: req.body.email }
            ]
        });

        if (existingUser) {
            return res.status(400).json({ error: 'Username or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            username: req.body.username,
            password: hashedPassword,
            email: req.body.email,
            name: req.body.name,
            fullName: req.body.name,
            year: req.body.year,
            phone: req.body.phone,
            mobile: req.body.mobile,
            address: req.body.address
        });

        await user.save();
        res.json({ message: 'Registration successful' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Error registering user' });
    }
});

// User login
app.post('/login', async (req, res) => {
    try {
        const user = await User.findOne({ username: req.body.username });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const validPassword = await bcrypt.compare(req.body.password, user.password);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        req.session.userId = user._id;
        res.json({ 
            message: 'Login successful',
            user: {
                username: user.username,
                email: user.email,
                name: user.name
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Error logging in' });
    }
});

// Get user profile
app.get('/api/profile', authenticateUser, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId)
            .select('-password -__v'); // Exclude sensitive fields

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json(user);
    } catch (error) {
        console.error('Profile fetch error:', error);
        res.status(500).json({ error: 'Error fetching profile' });
    }
});

// Update user profile
app.put('/api/profile', authenticateUser, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Update only the fields that are provided
        if (req.body.name) user.name = req.body.name;
        if (req.body.fullName) user.fullName = req.body.fullName;
        if (req.body.email) user.email = req.body.email;
        if (req.body.phone) user.phone = req.body.phone;
        if (req.body.mobile) user.mobile = req.body.mobile;
        if (req.body.address) user.address = req.body.address;

        await user.save();
        res.json({ message: 'Profile updated successfully' });
    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ error: 'Error updating profile' });
    }
});

// Update social links
app.put('/api/profile/social', authenticateUser, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.socialLinks) {
            user.socialLinks = {};
        }

        // Update only the social links that are provided
        if (req.body.github !== undefined) user.socialLinks.github = req.body.github;
        if (req.body.twitter !== undefined) user.socialLinks.twitter = req.body.twitter;
        if (req.body.instagram !== undefined) user.socialLinks.instagram = req.body.instagram;
        if (req.body.facebook !== undefined) user.socialLinks.facebook = req.body.facebook;

        await user.save();
        res.json({ 
            message: 'Social links updated successfully',
            socialLinks: user.socialLinks
        });
    } catch (error) {
        console.error('Social links update error:', error);
        res.status(500).json({ error: 'Error updating social links' });
    }
});

// Upload profile photo
app.post('/api/profile/photo', authenticateUser, uploadProfilePhoto.single('photo'), async (req, res) => {
    try {
        // Verify file exists
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Verify user exists
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Verify file was saved to disk
        const newPhotoPath = path.join(__dirname, 'uploads', 'profiles', req.file.filename);
        if (!fs.existsSync(newPhotoPath)) {
            throw new Error('File was not saved to disk');
        }

        // Delete old photo if it exists and isn't default
        if (user.profilePhoto && user.profilePhoto !== 'default-avatar.png') {
            const oldPhotoPath = path.join(__dirname, 'uploads', 'profiles', user.profilePhoto);
            if (fs.existsSync(oldPhotoPath)) {
                fs.unlinkSync(oldPhotoPath);
            }
        }

        // Update user in database
        user.profilePhoto = req.file.filename;
        await user.save();

        // Verify update in database
        const updatedUser = await User.findById(req.session.userId);
        if (updatedUser.profilePhoto !== req.file.filename) {
            throw new Error('Database update failed');
        }

        res.json({ 
            success: true,
            message: 'Profile photo updated successfully',
            filename: req.file.filename
        });

    } catch (error) {
        console.error('Photo upload error:', error);
        
        // Clean up if something went wrong
        if (req.file) {
            const tempPath = path.join(__dirname, 'uploads', 'profiles', req.file.filename);
            if (fs.existsSync(tempPath)) {
                fs.unlinkSync(tempPath);
            }
        }
        
        res.status(500).json({ 
            success: false,
            error: error.message || 'Error uploading photo' 
        });
    }
});

// Remove profile photo
app.delete('/api/profile/photo', authenticateUser, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Delete current photo if it's not the default
        if (user.profilePhoto !== 'default-avatar.png') {
            const fs = require('fs');
            const photoPath = path.join(__dirname, 'uploads', 'profiles', user.profilePhoto);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
        }

        user.profilePhoto = 'default-avatar.png';
        await user.save();

        res.json({ message: 'Profile photo removed successfully' });
    } catch (error) {
        console.error('Photo removal error:', error);
        res.status(500).json({ error: 'Error removing photo' });
    }
});

// Add certificate
app.post('/api/profile/certificates', authenticateUser, uploadCertificate.single('certificateFile'), async (req, res) => {
    try {
        const { name, issuer, date, description } = req.body;
        
        if (!name || !issuer || !date) {
            return res.status(400).json({ error: 'Name, issuer and date are required' });
        }

        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const certificate = {
            name,
            issuer,
            date: new Date(date),
            description,
            fileUrl: req.file ? `/uploads/certificates/${req.file.filename}` : null
        };

        if (!user.certificates) {
            user.certificates = [];
        }

        user.certificates.push(certificate);
        await user.save();

        res.json(certificate);
    } catch (error) {
        console.error('Certificate upload error:', error);
        res.status(500).json({ error: 'Failed to add certificate' });
    }
});

// Logout
app.post('/logout', authenticateUser, (req, res) => {
    req.session.destroy(err => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Error logging out' });
        }
        res.clearCookie('connect.sid');
        res.json({ message: 'Logged out successfully' });
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    
    // Handle multer errors
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(413).json({ error: 'File size too large' });
        }
        return res.status(400).json({ error: 'File upload error' });
    }
    
    // Handle other errors
    res.status(500).json({ error: 'Something went wrong!' });
});

// Serve HTML files
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'mainproj.html'));
});

app.get('/profile', authenticateUser, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Uploads directory: ${path.join(__dirname, 'uploads')}`);
});

// Ensure upload directories exist
const fs = require('fs');
const uploadDirs = ['profiles', 'certificates'];
uploadDirs.forEach(dir => {
    const dirPath = path.join(__dirname, 'uploads', dir);
    if (!fs.existsSync(dirPath)) {
        fs.mkdirSync(dirPath, { recursive: true });
        console.log(`Created upload directory: ${dirPath}`);
    }
});