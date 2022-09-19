const bcrypt = require("bcrypt");
const { Router } = require("express");
const { toJWT } = require("../auth/jwt");
const authMiddleware = require("../auth/middleware");
const User = require("../models/").user;
const { SALT_ROUNDS } = require("../config/constants");

const router = new Router();

//login
router.post("/login", async (req, res, next) => {
  try {
    const { name, password } = req.body;

    if (!name || !password) {
      return res
        .status(400)
        .send({ message: "Please provide both name and password" });
    }

    const user = await User.findOne({ where: { name } });

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(400).send({
        message: "User with that name not found or password incorrect",
      });
    }

    delete user.dataValues["password"]; // don't send back the password hash
    const token = toJWT({ userId: user.id });
    return res.status(200).send({ token, user: user.dataValues });
  } catch (error) {
    console.log(error);
    return res.status(400).send({ message: "Something went wrong, sorry" });
  }
});

//signup
router.post("/signup", async (req, res) => {
  const { password, name } = req.body;
  if (!password || !name) {
    return res.status(400).send("Please provide password and a name");
  }

  try {
    const newUser = await User.create({
      password: bcrypt.hashSync(password, SALT_ROUNDS),
      name,
    });

    delete newUser.dataValues["password"]; // don't send back the password hash

    const token = toJWT({ userId: newUser.id });

    res.status(201).json({ token, user: newUser.dataValues });
  } catch (error) {
    if (error.name === "SequelizeUniqueConstraintError") {
      return res
        .status(400)
        .send({ message: "There is an existing account with this email" });
    }

    return res.status(400).send({ message: "Something went wrong, sorry" });
  }
});

// The /me endpoint can be used to:
// - get the users email & name using only their token
// - checking if a token is (still) valid
router.get("/me", authMiddleware, async (req, res) => {
  // don't send back the password hash
  delete req.user.dataValues["password"];
  res.status(200).send({ ...req.user.dataValues });
});
//http PATCH :4000/auth/1 checkPoint=3 highScore=20
router.patch("/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    const { checkPoint, highScore } = req.body;
    const scoreToUpdate = await User.findByPk(id);

    if (!scoreToUpdate) {
      res.status(404).send("User not found");
    }
    const updated = await scoreToUpdate.update({ checkPoint, highScore });
    res.send(updated);
  } catch (e) {
    console.log(e.message);
    next(e);
  }
});

//http DELETE :4000/auth/1
router.delete("/:id", authMiddleware, async (req, res, next) => {
  try {
    const { id } = req.params;
    const userToDelete = await User.findByPk(id);
    await userToDelete.destroy();
    res.send("User teminated");
  } catch (e) {
    console.log(e.message);
    next(e);
  }
});

module.exports = router;
