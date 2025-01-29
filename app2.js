const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const fs = require('fs');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const csrf = require('csurf');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'database.json');

// Middleware for security
app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cookieParser());

// Static file serving
app.use('/public', express.static(path.join(__dirname, 'public'))); // Publicly accessible
app.use('/protected', (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  next();
});
app.use('/protected', express.static(path.join(__dirname, 'private/protected'))); // Protected routes

// Session management
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'strong_secret_key',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
    },
  })
);

// CSRF protection
const csrfProtection = csrf({ cookie: true });
app.use(csrfProtection);

// Rate limiting for login
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // Limit each IP to 10 login requests per windowMs
  message: 'Too many login attempts. Please try again later.',
});

// Utility functions
const sanitizeInput = (input) => input.replace(/[<>"'/]/g, '');

const readData = async () => {
  try {
    const data = await fs.promises.readFile(DATA_FILE, 'utf8');
    return JSON.parse(data);
  } catch (err) {
    console.error('Error reading database:', err);
    return { users: [], tasks: [] };
  }
};

const writeData = async (data) => {
  try {
    await fs.promises.writeFile(DATA_FILE, JSON.stringify(data, null, 2), {
      flag: 'w',
    });
  } catch (err) {
    console.error('Error writing to database:', err);
  }
};

// Routes

// Home route
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/public/login.html');
  }
  res.redirect('/protected/dashboard.html');
});

// Route to provide CSRF token
app.get('/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

// Register route
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  console.log("Received register request:", username, password);
  const sanitizedUsername = sanitizeInput(username);

  if (!sanitizedUsername || !password) {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  try {
    const data = await readData();
    if (data.users.find((u) => u.username === sanitizedUsername)) {
      return res.status(400).json({ error: 'Username already exists.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    data.users.push({ username: sanitizedUsername, password: hashedPassword });
    await writeData(data);

    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Login route
app.post('/login', loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  console.log("Login attempt by:", username);
  const sanitizedUsername = sanitizeInput(username);

  try {
    const data = await readData();
    const user = data.users.find((u) => u.username === sanitizedUsername);
    console.log("User found in DB:", user);

    if (!user || !(await bcrypt.compare(password, user.password))) {
      console.log("Invalid credentials for:", username);
      return res.status(401).json({ error: 'Invalid credentials.' });
    }

    req.session.user = { username: user.username };
    res.redirect('/protected/dashboard.html');
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to log out.' });
    }
    res.clearCookie('connect.sid');
    res.redirect('/public/login.html');
  });
});

// Add task route
app.post('/add', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  const { taskName, description } = req.body;
  const sanitizedTaskName = sanitizeInput(taskName);
  const sanitizedDescription = sanitizeInput(description);

  try {
    const data = await readData();
    data.tasks.push({
      id: Date.now().toString(),
      taskName: sanitizedTaskName,
      description: sanitizedDescription,
      owner: req.session.user.username,
    });
    await writeData(data);

    res.redirect('/protected/dashboard.html');
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Get tasks route
app.get('/tasks', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  try {
    const data = await readData();
    const userTasks = data.tasks.filter((task) => task.owner === req.session.user.username);
    res.json(userTasks);
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Delete task route
app.delete('/tasks/:id', async (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  const { id } = req.params;

  try {
    const data = await readData();
    const taskIndex = data.tasks.findIndex(
      (t) => t.id === id && t.owner === req.session.user.username
    );

    if (taskIndex === -1) {
      return res.status(404).json({ error: 'Task not found or unauthorized.' });
    }

    data.tasks.splice(taskIndex, 1);
    await writeData(data);

    res.json({ message: 'Task deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error.' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});