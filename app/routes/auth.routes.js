const verifyUser = require("../middleware/verifyUser");
const controller = require("../controllers/auth.controller");
const express = require("express");
const router = express.Router();

// middleware router
router.use((req,res,next)=>{
    res.header(
        "Access-Control-Allow-Headers",
        "Origin, Content-Type, Accept"
      );
      next();
  });

// router
router.post("/signup",[verifyUser.checkDuplicateUsernameOrEmail],controller.signup);
router.post("/signin", controller.signin);
router.post("/signout", controller.signout);
router.post("/reset",[verifyUser.checkExistUsernameOrEmail], controller.reset);


module.exports = router;
