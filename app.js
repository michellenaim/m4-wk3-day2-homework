const express = require("express");
const app = express();
const mongoose = require("mongoose");
const passport = require("passport");
const bodyParser = require("body-parser");
const LocalStrategy = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const User = require("./models/user");
const mongoSanitize = require("express-mongo-sanitize");
const rateLimit = require("express-rate-limit");
const xss = require("xss-clean");
const helmet = require("helmet");

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

const expSession = require("express-session")({
  secret: "mysecret", //decode or encode session
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    secure: true,
    maxAge: 1 * 60 * 1000,
  },
});

passport.use(new LocalStrategy(User.authenticate()));
app.use(expSession);
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());
passport.serializeUser(User.serializeUser()); //session encoding
passport.deserializeUser(User.deserializeUser()); //session decoding

//=======================
//      O W A S P
//=======================
app.use(mongoSanitize);

const limit = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests",
});
app.use("/routeName", limit);

app.use(express.json({ limit: "10kb" }));

app.use(xss());

app.use(helmet());

//=======================
//      R O U T E S
//=======================

app.get("/", (req, res) => {
  res.render("home");
});
app.get("/userprofile", (req, res) => {
  res.render("userprofile");
});
//Auth Routes
app.get("/login", (req, res) => {
  res.render("login");
});
app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/userprofile",
    failureRedirect: "/login",
  }),
  function (req, res) {}
);
app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  User.register(
    new User({
      username: req.body.username,
      email: req.body.email,
      phone: req.body.phone,
    }),
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.render("register");
      }
      passport.authenticate("local")(req, res, function () {
        res.redirect("/login");
      });
    }
  );
});
app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000, function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log("Server Started At Port 3000");
  }
});
