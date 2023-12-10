const User = require("../models/user.model");

// checkDuplicateUsernameOrEmail

exports.checkDuplicateUsernameOrEmail = async (req, res, next) => {
  try {
    // Username
    let existUser = await User.findOne({
      username: req.body.username,
    });

    if (existUser) {
      return res.status(400).send({
        message: "Failed! Username is already exist!",
      });
    }

    // Email
    let existEmail = await User.findOne({
      email: req.body.email,
    });

    if (existEmail) {
      return res.status(400).send({
        message: "Failed! Email is already exist!",
      });
    }

    next();
  } catch (error) {
    return res.status(500).send({
      message: error.message,
    });
  }
};

// checkExistUsernameOrEmail

exports.checkExistUsernameOrEmail = async (req, res, next) => {
  try {
    // Username
    
    const existUser = await User.findOne({
      $or: [{ username: req.body.username }, { email: req.body.email }],
    });

    if (!existUser) {
      return res.status(400).send({
        message: "Failed! User does not exist!",
      });
    }

    next();
  } catch (error) {
    return res.status(500).send({
      message: error.message,
    });
  }
};
