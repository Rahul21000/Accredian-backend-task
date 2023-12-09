const User = require("../models/user.model");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
dotenv.config();

const secret_key = process.env.SECRET_KEY;
const algorithm = process.env.ALGORITHM;
const your_email = process.env.YOUR_EMAIL;
const reset_url = process.env.RESET_URL;
const password = process.env.PASSWORD;

exports.signup = async (req, res) => {
  try {
    const createUser = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 12),
      cpassword: bcrypt.hashSync(req.body.password, 12),
    });

    if (createUser) res.send({ message: "User registered successfully!" });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};

exports.signin = async (req, res) => {
  try {
    const user = await User.findOne({
      $or: [{ username: req.body.username }, { email: req.body.email }],
    });

    if (!user) {
      return res.status(404).send({ message: "User Not found." });
    }

    const passwordIsValid = bcrypt.compareSync(
      req.body.password,
      user.password
    );

    if (!passwordIsValid) {
      return res.status(401).send({
        message: "Invalid Password!",
      });
    }

    const token = jwt.sign({ username: user.username }, secret_key, {
      algorithm: algorithm,
      allowInsecureKeySizes: true,
      expiresIn: 129600, // 36 hours
    });

    req.session.token = token;

    return res.status(200).send({
      username: user.username,
      email: user.email,
      token: token,
    });
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: your_email,
    pass: password,
  },
});

exports.signout = async (req, res) => {
  try {
    req.session = null;
    return res.status(200).send({
      message: "You've been signed out!",
    });
  } catch (err) {
    this.next(err);
  }
};

exports.reset = async (req, res) => {
  try {
    const existUser = await User.findOne({
      $or: [{ username: req.body.username }, { email: req.body.email }],
    });

    const resetToken = jwt.sign({ username: req.body.username }, secret_key, {
      // algorithm: ["HS256"],
      allowInsecureKeySizes: true,
      expiresIn: 144000,
    });

    const mailOption = {
      from: your_email,
      to: existUser.email,
      subject: "Password Reset",
      text: `Click on the following link to reset your password: ${reset_url}/${resetToken}`,
    };
    transporter.sendMail(mailOption, (err, info) => {
      if (err) {
        res.status(500).send({ message: err.message });
      } else {
        return res.status(200).send({
          email: `password reset sent to your ${existUser.email}`,
          info: `Email sent ${info.response}`,
        });
      }
    });
  } catch (err) {
    this.next(err);
  }
};
