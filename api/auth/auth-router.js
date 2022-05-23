// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require("express").Router();
const USER = require("../users/users-model");
const bycrypt = require("bcryptjs");
const {
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists,
} = require("./auth-middleware");

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */

router.post("/register", checkPasswordLength, checkUsernameFree, (req, res, next) => {
  const { username, password } = req.body;
  const hash = bycrypt.hashSync(password, 8);
  USER.add({ username, password: hash })
    .then((savedUser) => {
      res.status(201).json(savedUser);
    })
    .catch(next);
});

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post("/login", checkUsernameExists, (req, res, next) => {
  const { password } = req.body;
  if (bycrypt.compareSync(password, req.user.password)) {
    req.session.user = req.user;
    res.status(200).json({ message: `Welcome ${req.user.username}!` });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
});

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        next(err);
      } else {
        res.json({ message: "logged out" });
      }
    });
  } else {
    res.json({ message: "no session" });
  }
});

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router;
