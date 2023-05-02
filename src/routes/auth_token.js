import { Router } from "express";
import auth_by_email_password from "../helper/auth_by_email_password.js";
import { USERS_DATA } from "../bbdd.js";

const auth_token_router = Router();

// Authenticated endpoint
auth_token_router.post("/login", (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send();

  try {
    const user_data = auth_by_email_password(email, password);
    res.send(`You have been successfully authenticated ${user_data.name}`);
  } catch (err) {
    return res.status(401).send();
  }
});

// Obtain data while already authenticated with token
auth_token_router.get("/profile", (req, res) => {
  return res.send(`Welcome back`);
});

export default auth_token_router;