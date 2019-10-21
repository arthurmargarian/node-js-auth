const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const passport = require('passport');

//Login page
router.get('/login', (req, res) => res.render('login'));

//Register page
router.get('/register', (req, res) => res.render('register'));

//Register handle

router.post('/register', (req, res) => {
    const {name, username, password, password2} = req.body;
    let errors = [];

    //Check require fields
    if (!name || !username || !password || !password2) {
        errors.push({msg: 'Please fill all fields'});
    }
    //Check password match
    if (password !== password2) {
        errors.push({msg: 'Password do not match'});
    }
    //Check pass length
    if (password.length < 6) {
        errors.push({msg: 'Password should be least 6 characters'})
    }

    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            username,
            password,
            password2
        });
    } else {
        // Validation passed
        User.findOne({username: username})
            .then(user => {
                if (user) {
                    //User exists
                    errors.push({msg: 'User email is already registered'});
                    res.render('register', {
                        errors,
                        name,
                        username,
                        password,
                        password2
                    });
                } else {
                    const newUser = new User({
                        name,
                        username,
                        password
                    });
                    // Hash password
                    bcrypt.genSalt(10, (err, salt) =>
                        bcrypt.hash(newUser.password, salt, (err, hash) => {
                            if (err) throw err;
                            //set password to hashed
                            newUser.password = hash;
                            //Save User;
                            newUser.save()
                                .then(user => {
                                    req.flash('success_msg', 'You are now registered and can log in');
                                    res.redirect('/users/login');
                                })
                                .catch(err => console.log(err));
                        }))
                }
            })
    }
});

//Login handle

router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});

//Logout handle

router.get('/logout', (req, res) => {
    req.logout();
    req.flash('success_msg', 'You are log out');
    res.redirect('/users/login');
});

module.exports = router;
