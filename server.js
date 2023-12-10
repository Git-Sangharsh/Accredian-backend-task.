import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import mysql from "mysql2"; // Use mysql2 library
import bcrypt from "bcrypt";

const server = express();
server.use(bodyParser.json());
server.use(cors());
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "SangharshSql",
  database: "test",
});

server.get("/", (req, res) => {
  res.send("<h1>hello world</h1>");
});

server.get("/user", (req, res) => {
  const q = "SELECT * FROM user";
  db.query(q, (err, data) => {
    if (err) return res.json(err);
    return res.json(data);
  });
});


//this is signup
server.post("/user", (req, res) => {
  // Check if the email already exists in the user table
  const checkEmailQuery = "SELECT * FROM user WHERE email = ?";
  const checkEmailValues = [req.body.userEmail];

  db.query(checkEmailQuery, checkEmailValues, (checkEmailErr, checkEmailData) => {
    if (checkEmailErr) {
      return res.json({ error: checkEmailErr });
    }

    if (checkEmailData.length > 0) {
      return res.json({ error: 'Duplicate email' });
    }

    const saltRounds = 10;

    // Hash the password asynchronously
    bcrypt.hash(req.body.userPassword, saltRounds)
      .then((hashedPassword) => {
        const insertUserQuery = "INSERT INTO user (`username`, `password`, `email`) VALUES (?)";
        const userValues = [req.body.userName, hashedPassword, req.body.userEmail];

        db.query(insertUserQuery, [userValues], (err, userData) => {
          if (err) {
            return res.json({ error: err });
          }

          const insertSignInQuery = "INSERT INTO signin (`username`, `signinemail`, `signpassword`) VALUES (?)";
          const signInValues = [req.body.userName, req.body.userEmail, hashedPassword];

          db.query(insertSignInQuery, [signInValues], (signInErr, signInData) => {
            if (signInErr) {
              return res.json({ error: signInErr });
            }

            return res.json({
              user: "User registered successfully",
              signIn: "Data added to sign in successfully",
              backendSuccess: 'success'
            });
          });
        });
      })
      .catch((hashErr) => {
        return res.json({ error: hashErr });
      });
  });
});



server.post("/signin", (req, res) => {
  const { userSignInEmail, userSignInPassword } = req.body;

  let q;
  let values;

  if (userSignInEmail.includes("@")) {
    // If userSignInEmail contains "@", treat it as signinemail
    q = "SELECT * FROM signin WHERE signinemail = ?";
    values = [userSignInEmail];
  } else {
    // If userSignInEmail does not contain "@", treat it as username
    q = "SELECT * FROM signin WHERE username = ?";
    values = [userSignInEmail];
  }

  db.query(q, values, (err, result) => {
    if (err) {
      return res.json({ error: err });
    }

    if (result.length > 0) {
      const hashedPassword = result[0].signpassword;

      bcrypt.compare(userSignInPassword, hashedPassword, (compareErr, passwordMatch) => {
        if (compareErr) {
          return res.json({ error: compareErr });
        }

        if (passwordMatch) {
          return res.json({ message: "Sign in successful", success: 'success' });
        } else {
          return res.json({ error: "Incorrect password" });
        }
      });
    } else {
      // No match found, sendingd an error response
      return res.json({ error: "User not found" });
    }
  });

});



server.listen(5000, () => {
  console.log("server is running on port 5000");
});
