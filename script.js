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
      const rows = await pool.query("SELECT * FROM User WHERE username = $1", [
        username,
      ]);
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
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const rows = await pool.query("SELECT * FROM User WHERE id = $1", [id]);
    const user = rows[0];
    return done(null, user);
  } catch (err) {
    done(err);
  }
});
// routes
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/signup", (req, res) => {
  res.render("signup");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

const accessPath = path.join(__dirname, "public");
app.use(express.static(accessPath));

// server start listening
app.listen(3000, (err) => {
  if (err) {
    console.error("Error starting server:", err);
  } else {
    console.log("Server is running on port 3000");
  }
});
