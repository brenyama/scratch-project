const express = require('express');
const db = require('../model/db.js');
const bcrypt = require('bcryptjs');
const saltRounds = 10;

const userController = {};

userController.createUser = (req, res, next) => {

  const queryText = `
    INSERT INTO users (account_name, password)
    VALUES ($1, $2)
    RETURNING _id
  `
  const { username, password } = req.body;
  

  bcrypt.genSalt(saltRounds, (err, salt) => {
    if(err) return next({
      log: 'Error in userController.createUser',
      status: 400,
      message: err,
    });

    bcrypt.hash(password, salt, (err, hash) => {

      if(err) return next({
        log: 'Error in userController.createUser',
        status: 400,
        message: err,
      });

      const values = [username, hash];
      db.query(queryText, values)
        .then(data => {
          res.locals.user = data.rows[0]
          return next();
        })
        .catch(err => next({
          log: 'Error in userController.createUser',
          status: 400,
          message: err,
        }));
      })
  })

  
}

userController.validateUser = (req, res, next) => {
  const { username, password } = req.body;
  const values = [username];

  const queryText = `
    SELECT * from users WHERE account_name = $1;
  `;

  db.query(queryText, values)
    .then(data => {

      const dbUser = data.rows[0]

      // check password make this more secure later with bcrypt 
      // if (dbUser.password === password) {
      //   res.locals.user = {
      //     account_name: dbUser.account_name,
      //     _id: dbUser._id,
      //   };
      //   return next();
      // }

      bcrypt.compare(password, dbUser.password, (err, result) => {

          if (result == true) {
            res.locals.user = {
              account_name: dbUser.account_name,
              _id: dbUser_id
            }
            return next();
          }
      })
;
      return next({
        log: 'Error in userController.validateUser',
        status: 400,
        message: 'password did not match',
      })

    }).catch(err => next({
      log: 'Error in userController.validateUser',
      status: 400,
      message: err,
    }));
}

module.exports = userController;