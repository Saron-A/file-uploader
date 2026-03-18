require("dotenv").config();
import express from "express";
import passport from "passport";
import session from "express-session";
import cors from "cors";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// routes

// server start listening
app.listen(3000, (err) => {
  if (err) {
    console.error("Error starting server:", err);
  } else {
    console.log("Server is running on port 3000");
  }
});
