require("dotenv").config();
const express = require("express");
const passport = require("passport");
const session = require("express-session");
const localStrategy = require("passport-local").Strategy;
const pool = require("./db/pool.js");
const bcrypt = require("bcryptjs");
const cors = require("cors");
const path = require("path");
const fs = require("node:fs");
const upload = require("./multerConfig.js");

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
app.get("/", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const files = await pool.query("SELECT * FROM files WHERE user_id = $1", [
        req.user.id,
      ]);
      console.log(files.rows); // returns array of files -- files.rows

      const folders = await pool.query(
        "SELECT * FROM folders WHERE user_id = $1",
        [req.user.id],
      );
      console.log(folders.rows); // returns arrays of folders -- folders.rows

      res.render("index", {
        user: req.user,
        files: files.rows,
        folders: folders.rows,
      });
    } catch (err) {
      console.error("Error rendering index page:", err);
    }
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

app.get("/dashboard", async (req, res) => {
  if (req.isAuthenticated()) {
    try {
      const files = await pool.query("SELECT * FROM files WHERE user_id = $1", [
        req.user.id,
      ]);
      console.log(files.rows); // returns array of files -- files.rows

      const folders = await pool.query(
        "SELECT * FROM folders WHERE user_id = $1",
        [req.user.id],
      );
      console.log(folders.rows); // returns arrays of folders -- folders.rows

      res.render("dashboard", {
        user: req.user,
        files: files.rows,
        folders: folders.rows,
      });
    } catch (err) {
      console.error("Error rendering index page:", err);
    }
  } else {
    res.status(401).send("Unauthorized");
  }
});

app.get("/folders/:folderId", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }
  try {
    const { folderId } = req.params;
    const files = await pool.query(
      "SELECT * FROM files WHERE folder_id = $1 AND user_id = $2",
      [folderId, req.user.id],
    );
    return res.render("folderContents", { user: req.user, files: files.rows });
  } catch (err) {
    console.error("Error fetching folder contents:", err);
  }
});

app.get("/profile", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("profile", { user: req.user });
  }
});

app.get("/createFolder", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }
  try {
    const { rows } = await pool.query(
      "SELECT * FROM files WHERE folder_id IS NULL AND user_id = $1",
      [req.user.id],
    );
    return res.render("createFolder", { user: req.user, files: rows });
  } catch (err) {
    console.error("Error rendering create folder page:", err);
  }
});

app.post("/createFolder", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const { name } = req.body;
    await pool.query("INSERT INTO folders (name, user_id) VALUES ($1, $2)", [
      name,
      req.user.id,
    ]);
    console.log("Folder created successfully");
    return res.redirect("/upload");
  } catch (err) {
    console.error("Error creating folder:", err);
    return res.status(500).send("Error creating folder");
  }
});

app.get("/upload", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const { rows } = await pool.query(
      "SELECT * FROM folders WHERE user_id = $1",
      [req.user.id],
    );

    return res.render("upload", { user: req.user, folders: rows });
  } catch (err) {
    console.error("Error rendering upload page:", err);
  }
});

app.post("/upload", upload.single("file"), async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const file = req.file;
    const folderId = parseInt(req.body.folderId);
    if (!folderId) {
      return res.status(400).send("Folder is required");
    }

    await pool.query(
      "INSERT INTO files (name, path,size, folder_id, user_id) VALUES ($1, $2, $3, $4, $5)",
      [file.originalname, file.path, file.size, folderId, req.user.id],
    );

    console.log(file);
    res.send("File uploaded successfully");
  } catch (err) {
    console.error("UPLOAD ERROR:", err);
    res.status(500).send("Error uploading file");
  }
});

app.get("/files/:fileId", async (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).send("Unauthorized");
  }

  try {
    const { fileId } = req.params;
    // through the id find the file path in the database
    // then send the file to the client - display the content or make it downloadable
    const { rows } = await pool.query(
      "SELECT * FROM files Where id = $1 AND user_id = $2",
      [fileId, req.user.id],
    ); // returns a single file object in an array

    const file = rows[0];
    const filePath = file.path;

    // display the content of the file in the browser if it's a text file, otherwise make it downloadable
    const ext = path.extname(file.name).toLowerCase();
    if (ext === ".txt") {
      const fileData = fs.readFileSync(filePath, "utf-8");
      res.setHeader("Content-Type", "text/plain");
      return res.render("fileContents", { content: fileData });
    } else {
      return res.download(filePath, file.name);
    }
  } catch (err) {
    console.error("Error fetching file:", err);
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
