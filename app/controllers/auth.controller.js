const User = require("../models/user.model");
const config = require("../config/auth.config");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

exports.signup = async (req, res) => {
  try {
    const createUser = await User.create({
      username: req.body.username,
      email: req.body.email,
      password: bcrypt.hashSync(req.body.password, 12),
      cpassword: bcrypt.hashSync(req.body.password, 12),
    });

    if (createUser) res.send({ message: "Registered successfully!" });
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
      return res.status(404).send({ message: "User Not found!" });
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

    const token = jwt.sign({ username: user.username }, config.secret_key, {
      algorithm: config.algorithm,
      allowInsecureKeySizes: true,
      expiresIn: 129600, // 36 hours
    });
    
    req.session.token = token;

    return res.status(200).send({
      message: "You've been signed in!",
    });
  } catch (error) {
    return res.status(500).send({ message: error.message });
  }
};

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: config.your_email,
    pass: config.password,
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

    const resetToken = jwt.sign(
      { username: req.body.username },
      config.secret_key,
      {
        // algorithm: ["HS256"],
        allowInsecureKeySizes: true,
        expiresIn: 144000,
      }
    );

    const mailOption = {
      from: config.your_email,
      to: existUser.email,
      subject: "Password Reset",
      text: `Click on the following link to reset your password: ${config.reset_url}/${config.resetToken}`,
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
