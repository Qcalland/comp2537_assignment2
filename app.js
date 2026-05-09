require("./utils.js");
require("dotenv").config();
const express = require("express");
const path = require("path");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const bcrypt = require("bcrypt");
const saltRounds = 12;

const app = express();

const Joi = require("joi");
const mongoSanitizer = require("mongo-sanitizer").default;
//import mongoSanitizer from 'mongo-sanitizer';

const PORT = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_user_database = process.env.MONGODB_USER_DATABASE;
const mongodb_session_database = process.env.MONGODB_SESSION_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

const requiredEnvVars = [
  "MONGODB_HOST",
  "MONGODB_USER",
  "MONGODB_PASSWORD",
  "MONGODB_USER_DATABASE",
  "MONGODB_SESSION_DATABASE",
  "MONGODB_SESSION_SECRET",
  "NODE_SESSION_SECRET",
];
const missingEnvVars = requiredEnvVars.filter((name) => !process.env[name]);
if (missingEnvVars.length > 0) {
  console.error(
    "Missing required environment variables: " + missingEnvVars.join(", "),
  );
  console.error(
    "Add them in the Render dashboard: Service → Environment → Environment Variables (or use a .env file locally).",
  );
  process.exit(1);
}

const { database } = include("databaseConnection");
const userCollection = database.db(mongodb_user_database).collection("users");

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

app.use(
  "/vendor/bootstrap",
  express.static(path.join(__dirname, "node_modules", "bootstrap", "dist")),
);

app.use(mongoSanitizer({ replaceWith: "_" }));

var mongoStore = MongoStore.create({
  mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/${mongodb_session_database}`,
  crypto: {
    secret: mongodb_session_secret,
  },
});

app.use(
  session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store
    saveUninitialized: false,
    resave: true,
    cookie: {
      maxAge: expireTime,
    },
  }),
);

app.use((req, res, next) => {
  res.locals.authenticated = Boolean(req.session?.authenticated);
  res.locals.name = req.session?.name;
  res.locals.user_type = req.session?.user_type;
  res.locals.path = req.path;
  next();
});

function isValidSession(req) {
  if (req.session.authenticated) {
    return true;
  }
  return false;
}

function sessionValidation(req, res, next) {
  if (isValidSession(req)) {
    next();
  } else {
    res.redirect("/login");
  }
}

function isAdmin(req) {
  if (req.session.user_type == "admin") {
    return true;
  }
  return false;
}

function adminAuthorization(req, res, next) {
  if (!isAdmin(req)) {
    res.status(403);
    res.render("errorMessage", { error: "Not Authorized" });
    return;
  } else {
    next();
  }
}

app.get("/", (req, res) => {
  res.render("index", {
    authenticated: Boolean(req.session.authenticated),
    name: req.session.name,
    user_type: req.session.user_type,
  });
});

app.get("/signup", (req, res) => {
  if (isValidSession(req)) {
    res.redirect("/members");
    return;
  }

  res.render("signup", { error: null, values: { name: "", email: "" } });
});

app.post("/signup", async (req, res) => {
  const schema = Joi.object({
    name: Joi.string().trim().min(1).max(80).required(),
    email: Joi.string().trim().email().max(254).required(),
    password: Joi.string().min(8).max(128).required(),
  });

  const { error, value } = schema.validate(req.body, {
    abortEarly: true,
    convert: true,
  });

  if (error) {
    res.status(400);
    res.render("signup", {
      error: error.details[0].message,
      values: {
        name: String(req.body?.name ?? ""),
        email: String(req.body?.email ?? ""),
      },
    });
    return;
  }

  const normalizedEmail = value.email.toLowerCase();

  const existingUser = await userCollection.findOne({ email: normalizedEmail });
  if (existingUser) {
    res.status(400);
    res.render("signup", {
      error: "An account with that email already exists.",
      values: { name: value.name, email: value.email },
    });
    return;
  }

  const passwordHash = await bcrypt.hash(value.password, saltRounds);

  const newUser = {
    name: value.name,
    email: normalizedEmail,
    password: passwordHash,
    user_type: "user",
  };

  await userCollection.insertOne(newUser);

  req.session.authenticated = true;
  req.session.name = newUser.name;
  req.session.email = newUser.email;
  req.session.user_type = newUser.user_type;

  res.redirect("/members");
});

app.get("/login", (req, res) => {
  if (isValidSession(req)) {
    res.redirect("/members");
    return;
  }

  res.render("login", { error: null, values: { email: "" } });
});

app.post("/login", async (req, res) => {
  const schema = Joi.object({
    email: Joi.string().trim().email().max(254).required(),
    password: Joi.string().min(1).max(128).required(),
  });

  const { error, value } = schema.validate(req.body, {
    abortEarly: true,
    convert: true,
  });

  if (error) {
    res.status(400);
    res.render("login", {
      error: error.details[0].message,
      values: { email: String(req.body?.email ?? "") },
    });
    return;
  }

  const normalizedEmail = value.email.toLowerCase();
  const user = await userCollection.findOne({ email: normalizedEmail });

  if (!user) {
    res.status(401);
    res.render("login", {
      error: "Invalid email or password.",
      values: { email: value.email },
    });
    return;
  }

  const passwordOk = await bcrypt.compare(value.password, user.password);
  if (!passwordOk) {
    res.status(401);
    res.render("login", {
      error: "Invalid email or password.",
      values: { email: value.email },
    });
    return;
  }

  req.session.authenticated = true;
  req.session.name = user.name;
  req.session.email = user.email;
  req.session.user_type = user.user_type;

  res.redirect("/members");
});

app.get("/members", (req, res) => {
  if (!isValidSession(req)) {
    res.redirect("/");
    return;
  }

  res.render("members", { name: req.session.name });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
  const users = await userCollection
    .find({}, { projection: { password: 0 } })
    .sort({ email: 1 })
    .toArray();

  res.render("admin", { name: req.session.name, users });
});

app.post(
  "/admin/promote",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const schema = Joi.object({
      email: Joi.string().trim().email().max(254).required(),
    });

    const { error, value } = schema.validate(req.body, {
      abortEarly: true,
      convert: true,
    });

    if (error) {
      res.status(400);
      res.render("errorMessage", { error: error.details[0].message });
      return;
    }

    await userCollection.updateOne(
      { email: value.email.toLowerCase() },
      { $set: { user_type: "admin" } },
    );

    res.redirect("/admin");
  },
);

app.post(
  "/admin/demote",
  sessionValidation,
  adminAuthorization,
  async (req, res) => {
    const schema = Joi.object({
      email: Joi.string().trim().email().max(254).required(),
    });

    const { error, value } = schema.validate(req.body, {
      abortEarly: true,
      convert: true,
    });

    if (error) {
      res.status(400);
      res.render("errorMessage", { error: error.details[0].message });
      return;
    }

    await userCollection.updateOne(
      { email: value.email.toLowerCase() },
      { $set: { user_type: "user" } },
    );

    res.redirect("/admin");
  },
);

app.use(express.static(__dirname + "/public"));

app.use((req, res) => {
  res.status(404);
  res.render("404");
});

async function start() {
  await database.connect();
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
}

start().catch((err) => {
  console.error("Server failed to start:", err);
  process.exit(1);
});
