const express = require("express");
const app = express();
const port = 3001;
const mongo = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcrypt");
const dotenv = require("dotenv");
const nodemailer = require("nodemailer");
const passport = require("passport");
const localStragey = require("passport-local").Strategy;
const jwt = require("jsonwebtoken");
dotenv.config();
app.use(cors());
app.use(express.json());

// const MongoURL = "mongodb://localhost:27017/React-Mongo";
const AtlasMongoURL =
  "mongodb+srv://saisanthosh20802:S20802@cluster0.ridy1tv.mongodb.net/";

//MongoDb Connection
mongo
  .connect(AtlasMongoURL)
  .then(() => console.log("Database connection successful"))
  .catch(() => console.log("Database connection unsuccessful"));

//MongoDb Schema
const useSchema = new mongo.Schema({
  username: {
    required: true,
    type: String,
    unique: true,
  },
  password: {
    required: true,
    type: String,
  },
});

//Hashing the password using Bcrypt
useSchema.pre("save", async function (next) {
  const person = this;

  try {
    const salt = await bcrypt.genSalt(10);
    const hashedPassed = await bcrypt.hash(person.password, salt);

    person.password = hashedPassed;
    next();
  } catch (error) {
    return next(error);
  }
  // const salt = await bcrypt.genSalt(10);
  // this.password = await bcrypt.hash(this.password, salt);
  // next();
});

//Comparing the hashed password with method
useSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    const isMatch = await bcrypt.compare(candidatePassword, this.password);
    return isMatch;
  } catch (error) {
    throw error;
  }
};

const useModel = mongo.model("reactusers", useSchema);

//NodeMailer
const transporter = nodemailer.createTransport({
  host: process.env.SMPT_HOST,
  port: process.env.SMPT_PORT,
  secure: false, // Use `true` for port 465, `false` for all other ports
  auth: {
    user: process.env.SMPT_MAIL,
    pass: process.env.SMPT_PASSWORD,
  },
});

app.post("/", function (req, res) {
  const { subject, message } = req.body;

  var mailOptions = {
    from: process.env.SMPT_MAIL,
    to: "saisanthosh20802@gmail.com",
    subject: subject,
    text: message,
  };
  transporter.sendMail(mailOptions, function (err, res) {
    if (err) {
      console.log(err);
      res.status(500).json({ error: "Failed to send email" });
    } else {
      res.status(200).json({ message: "Email sent successfully" });
    }
  });
});

//Middleware Function to log which URL Visted
const logRequest = (req, res, next) => {
  console.log(
    `[${new Date().toLocaleString()}] Request Made to : ${req.originalUrl}`
  );
  next();
};

app.use(logRequest);

//Using passport to use Local Authentication
passport.use(
  new localStragey(async (username, password, done) => {
    try {
      const user = await useModel.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "incorrect username" });
      }
      const isPasswordMatch = await user.comparePassword(password);
      if (isPasswordMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: "Incorrect Password" });
      }
    } catch (error) {
      return done(error);
    }
  })
);

//Initialising the passwort middleware and it's Authentication
app.use(passport.initialize());
const localAuthMiddleware = passport.authenticate("local", { session: false });

const jwtAuthMiddleware = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization) return res.status(401).json({ error: "Token not found" });

  const token = req.headers.authorization.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();
  } catch (error) {
    console.error(error);
    res.status(401).json({ error: "Invalid token" });
  }
};

const generateToken = (userData) => {
  return jwt.sign(userData, process.env.JWT_SECRET, { expiresIn: "30000" });
};

app.get("/user", async (req, res) => {
  try {
    const result = await useModel.find({});
    res.status(200).json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/userLogin", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await useModel.findOne({
      username: username,
    });

    console.log("Result: ", result);

    if (result) {
      const isPasswordMatch = await result.comparePassword(password);

      console.log("Matched Password ", isPasswordMatch);

      if (isPasswordMatch) {
        res.status(200).json({ message: "Login Successfull", data: result });
      } else {
        res.status(400).json("Incorrect Password");
      }
    } else {
      res.status(400).json("No such record exists");
    }

    const payLoad = {
      id: result.id,
      username: result.username,
    };

    const token = generateToken(payLoad);
    res.json({ token });
    // console.log(result);
  } catch (error) {
    res.status(400).json({ error: "Cannot find the user" });
  }
});

app.post("/userSign", async (req, res) => {
  const { username, password } = req.body;

  try {
    const start = await useModel.create({
      username: username,
      password: password,
    });
    // res.status(200).json("User Created Successfully");

    const payLoad = {
      id: start.id,
      username: start.username,
    };

    const token = generateToken(payLoad);
    console.log("token: ", token);
    res.status(200).json({ response: start, token: token });
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({ error: "Username Already Exists" });
    } else {
      res.status(400).json({ error: error.message });
    }
  }
});

app.listen(port, () => console.log(`Example app listening on port ${port}!`));
