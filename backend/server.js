const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const mongoose = require('mongoose');
const authRoutes = require("./routes/authRoutes");
const cookieParser = require('cookie-parser');
dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(cookieParser()); // Middleware for JSON parsing
app.use(
  cors({
    origin: "http://localhost:3000", // Adjust if frontend URL is different
    credentials: true, // ✅ Allows frontend to send cookies
  })
);

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('✅ MongoDB Connected'))
  .catch(err => console.error('❌ MongoDB Connection Error:', err));

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
