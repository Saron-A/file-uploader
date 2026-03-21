require("dotenv").config();
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const localStrategy = require("passport-local").Strategy;
const pool = require("./db/pool.js");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// step 1: initialize passport

app.use(
  session({ secret: "something", resave: false, saveUninitialized: false }),
);
app.use(passport.initialize());
app.use(passport.session());

//Step 2: define a strategy
passport.use(
  new localStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username],
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "User not found" });
      }
      // Here you would typically compare the provided password with the hashed password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  }),
);
//Step 3: serialize and deserialize user
passport.serializeUser((user, done) => {
  return done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];
    return done(null, user);
  } catch (err) {
    done(err);
  }
});
// routes
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("index", { user: req.user });
  } else res.render("index", { user: null });
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.post("/signup", async (req, res) => {
  const { username, password, confirm_pass } = req.body;
  // check if user already exists
  //confirm password correctness
  try {
    const { rows } = await pool.query(
      "SELECT * FROM users WHERE username = $1",
      [username],
    );
    if (rows.length > 0) {
      return res.send("Username already exists");
    } else if (password !== confirm_pass) {
      return res.send("Passwords do not match");
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      await pool.query(
        "INSERT INTO users (username, password) VALUES ($1, $2)",
        [username, hashedPassword],
      );
      return res.status(200).send("User registered successfully");
    }
  } catch (err) {
    console.error("Error during signup:", err);
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) next(err);
    if (!user) {
      res.status(400).send(info.message);
    }

    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect("/");
    });
  })(req, res, next);
});

// current user
app.get("/current_user", (req, res) => {
  if (req.isAuthenticated()) {
    return res.json({ user: { id: req.user.id, username: req.user.username } });
  } else {
    res.status(401).json({ error: "Not logged in" });
  }
});

app.set("views", path.join(__dirname, "../src/views"));
app.set("view engine", "ejs");

const accessPath = path.join(__dirname, "../public");
app.use(express.static(accessPath));

// server start listening
app.listen(3000, (err) => {
  if (err) {
    console.error("Error starting server:", err);
  } else {
    console.log(`Server is running on http://localhost:3000`);
  }
});
