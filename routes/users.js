//include express
const express= require('express');

//include bcrypt to crypt password
const bcrypt = require('bcryptjs');
const gravatar = require('gravatar');

//include user model as you wanna use it
const User = require('../models/User');

//include body parser to access the information on page
const bodyParser = require('body-parser');

const keys = require('../config/keys');
const passport = require('passport');
const jwt = require('jsonwebtoken');


//Pull out router on express variable
const router = express.Router();
router.get('/test',(req,res) => res.json({"msg":"Using Router"}))

router.post('/registration',(req,res) => {
    User.findOne({ email: req.body.email }).then(user => {
        if (user) {
            return res.status(400).json({email:"Email already exists"});
          } else {
            const avatar = gravatar.url(req.body.email, {
              s: '200', // Size
              r: 'pg', // Rating
              d: 'mm' // Default
            });
      
        const newUser = new User({
           name:req.body.name,
           email:req.body.email,
           password:req.body.password,
           avatar
        });
        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(newUser.password, salt, (err, hash) => {
              if (err) throw err;
              newUser.password = hash;
              newUser
                .save()
                .then(user => res.json(user))
                .catch(err => console.log(err));
            });
          }); 
    }

});
});


router.post('/login',(req,res) => {
    const email = req.body.email;
    const password = req.body.password;
    
    User.findOne({ email}).then(user => {
        if (!user) {
            return res.status(400).json({email:"User account does not exist"});
          } 
        // Check Password
    bcrypt.compare(password, user.password).then(isMatch => {
        if (isMatch) {
          // User Matched
  
          const payload = { id: user.id, name: user.name, avatar: user.avatar }; // Create JWT Payload
  
          // Sign Token
          jwt.sign(
            payload,
            keys.secret,
            { expiresIn: 3600 },
            (err, token) => {
              res.json({
                success: true,
                token: 'Bearer ' + token
              });
            }
          );
        } else {
          return res.status(400).json({Password:'Password incorrect'});
        }
      });
    });
  });
//last step to export
module.exports = router;
