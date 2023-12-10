const express = require("express");
const router = express.Router();
const { authJwt } = require("../middleware/authJwt");
const controller = require("../controllers/user.controller");

module.exports = function () {
  router.use(function (req, res, next) {
    res.header("Access-Control-Allow-Headers", "Origin, Content-Type, Accept");
    next();
  });

  router.get("/all", [authJwt.verifyToken], controller.allAccess);

  router.get("/dashboard", [authJwt.verifyToken], controller.dashboard);
};
