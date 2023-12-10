const express = require("express");
const cookieSession = require("cookie-session");
const cors = require("cors");
const router = require("./app/routes/auth.routes");
const connectDB = require("./app/config/config.db");
const config = require("./app/config/auth.config");


const app = express();

//middleware
app.use(express.json());

app.use(
  cors({
    credentials: true,
    origin: [`http://localhost:${config.origin}`],
  })
);

app.use(express.urlencoded({ extended: true }));

app.use(
  cookieSession({
    name: "-session",
    keys: [config.cookies_key], 
    httpOnly: true,
    sameSite: 'strict'
  })
);

//use routes
app.use("/api/auth", router);

app.listen(config.port, async () => {
  console.log(`Server is running on port ${config.port}`);
  connectDB();
});
