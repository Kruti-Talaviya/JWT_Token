const express = require('express');
const { register, login } = require('../controllers/authController');
const protect = require('../middleware/authMiddleware');
// const { profile } = require('../controllers/userController'); // Import profile function

const router = express.Router();

router.post('/register', register);
router.post('/login', login);

// Protected route (Profile)
router.get('/profile', protect, (req, res) => {
  try {
    res.json({ message: 'Protected route accessed', user: req.user });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});


router.post("/logout", (req, res) => {
  res.cookie("token", "", { httpOnly: true, expires: new Date(0) }); // ✅ Clear cookie
  res.status(200).json({ message: "Logged out successfully" });
});



// router.get('/profile', protect, profile); // Use profile function

module.exports = router;
