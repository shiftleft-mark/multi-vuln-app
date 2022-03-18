const express = require('express');
const router = express.Router()

router.get('/greeting', (req, res) => {
    const { username, password }  = req.query;
    console.log(password);
    res.send("<h1> Hello World</h1>");
});

router.get('/greeting2', (req, res) => {
    if(req.session.isAuthenticated()) {
        console.log(req.query.password); // data leak
    }
    res.send("<h1> Hello World</h1>");
});

router.get('/greeting3', (req, res) => {
    const { username, password }  = req.query;
    let data = {}
    if(req.session.isAuthenticated()) {
        data.username = username;
        data.password = password;
    }
    console.log(data); // data leak
    res.send("<h1> Hello World</h1>");
});

router.get('/greeting4', (req, res) => {
    const { username, password }  = req.query;
    let request = {}
    if(req.session.isAuthenticated()) {
        request.foo = "bar";
    }
    console.log(request); // false positive
    res.send("<h1> Hello World</h1>");
});
