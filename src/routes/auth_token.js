import { Router } from "express";
import auth_by_email_password from "../helper/auth_by_email_password.js";
import { USERS_DATA } from "../bbdd.js";
import { SignJWT, jwtVerify } from "jose";

const auth_token_router = Router();

// Authenticated endpoint
auth_token_router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send();

  try {
    const user_data = auth_by_email_password(email, password);
    const guid = user_data.guid;

    /* TOKEN CREATION WITH 'SIGNJWT' */
    // PAYLOAD information
    const jwt_Constructor = new SignJWT({ guid });

    //The secret key for the signature must be in Uint8Array format.
    const encoder = new TextEncoder();
    const key = encoder.encode(process.env.JWT_KEY);

    // Returns Json Web Token
    const jwt = await jwt_Constructor
      // (About headers => https://jwt.io/)
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      // Date created
      .setIssuedAt()
      .setExpirationTime("1h")
      // Signature of the JWT as promise (hence the 'await')
      .sign(key);

    res.send({ jwt });
  } catch (err) {
    return res.status(401).send();
  }
});

// Obtain data while already authenticated with token
auth_token_router.get("/profile", async (req, res) => {
  /*
    Note: For practical reasons the token is sent in the header of the request, more specifically in the Authorization
  */
  // Token in header in authorization
  const { authorization } = req.headers;
  if (!authorization) return res.status(401).send();

  try {
    //The secret key for the signature must be in Uint8Array format.
    const encoder = new TextEncoder();
    const key = encoder.encode(process.env.JWT_KEY);
    // Verify that the JWT has not been altered, is valid and has not expired (with jwtVerify).
    const jwt_data = await jwtVerify(authorization, key);
    const payload = jwt_data.payload;
    const user_data = USERS_DATA.find((user) => user.guid === payload.guid);

    return res.send(`Welcome back ${user_data.name}`);
  } catch (err) {
    return res.status(401).send();
  }
});

export default auth_token_router;
