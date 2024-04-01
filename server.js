const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
app.use(bodyParser.json());
app.use(cors());

mongoose.connect('mongodb://localhost:27017/hrm', { useNewUrlParser: true });

const User = mongoose.model('User', {
  firstname: String,
  lastname: String,
  email: String,
  passwordHash: String,
  department: String,
  position: String,
  phonenumber: String
});

function generateAccessToken(user) {
  return jwt.sign(user, 'secret');
}

// Hashing function using Node.js crypto module
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

app.post('/register', async (req, res) => {
  try {
    const { firstname, lastname, email, password,department,position,phonenumber } = req.body;
    const passwordHash = hashPassword(password);
    const user = new User({ firstname, lastname, email, passwordHash,department,position,phonenumber });
    await user.save();
    const token = generateAccessToken({ firstname, email });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error registering new user.');
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).send('User not found.');
    }
    // Compare hashed password
    if (user.passwordHash !== hashPassword(password)) {
      return res.status(401).send('Invalid password.');
    }
    const token = generateAccessToken({ firstname: user.firstname, email });
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).send('Error logging in.');
  }
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
