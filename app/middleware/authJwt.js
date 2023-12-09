const jwt = require("jsonwebtoken");
const dotenv=require("dotenv");
dotenv.config();
const secret_key=process.env.SECRET_KEY

module.exports = (req, res, next) => {
  let token = req.session.token;

  if (!token) {
    return res.status(403).send({
      message: "No token provided!",
    });
  }

  jwt.verify(token,secret_key, (err, decoded) => {
    if (err) {
      return res.status(401).send({
        message: "Unauthorized!",
      });
    }
    req.username = decoded.username;
    next();
  });
};
