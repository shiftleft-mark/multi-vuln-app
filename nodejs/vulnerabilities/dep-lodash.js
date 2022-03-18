const express = require('express');
const router = express.Router()

const lodash = require('lodash');

//if req.body.config == '{"constructor": {"prototype": {"isAdmin": true}}}' it will bypass the authentication
function check(req, res) {

    let config = {};
    lodash.defaultsDeep(config, JSON.parse(req.body.config));

    let user = getCurrentUser(config);
    if(!user){
      user = {};
    }

    if (user.isAdmin && user.isAdmin === true) {
        res.send('Welcome Admin')
    }else{
        res.send('Welcome User')
    }
}

//fake function that get current user from session or db
function getCurrentUser(config){
  return config;
}

var merge = function(target, source) {
    for(var attr in source) {
        if(typeof(target[attr]) === "object" && typeof(source[attr]) === "object") {
            merge(target[attr], source[attr]);
        } else {
            target[attr] = source[attr];
        }
    }
    return target;
};

var pathAssignment = (obj, path, value) => {
    var segments = path.split(".");
    var key = segments.splice(0,1)[0];
    if(segments.length) {
        if(obj[key]) {
            obj[key] = pathAssignment(obj[key], segments.join('.'), value);
        } else {
            obj[key] = pathAssignment({}, segments.join('.'), value);
        }
    } else {
        obj[key] = value;
    }
    return obj;
};

function isValidUserConfig(userConfig) {
  if (!userConfig) {
    return false;
  }
  // Insufficient. Check constructor argument as well
  if (userConfig['__proto__'] || userConfig['prototype']) {
    return false;
  }
  return true;
}

function isValidUserConfigAlt(userConfig) {
  if (!userConfig) {
    return false;
  }
  for (var k in userConfig) {
    // Insufficient. Check for prototype and constructor as well
    if (userConfig[k] === '__proto__') {
        return false;
    }
  }
  return true;
}


router.post('/check-user',check)

router.get('/example1/user/:userConfig',  (req,res) => {
    let userConfig = req.params.userConfig;
    let config = {}
    merge(config, userConfig);
    res.send("Config is" + config);
});

router.get('/example2/user/:userConfig/:userPath',  (req,res) => {
    let userConfig = req.params.userConfig;
    let config = {}
    pathAssignment(config, req.params.userPath, userConfig);
    res.send("Config is" + config);
});

router.get('/example3/user/:userConfig',  (req,res) => {
    let userConfig = req.params.userConfig;
    let validationFailed = false;
    // Validate userConfig here
    if (!isValidUserConfig(userConfig)) {
      validationFailed = true;
    }
    if (!isValidUserConfigAlt(userConfig)) {
      res.send('Validation error');
    }
    let user = getCurrentUser(config);
    if (user.isAdmin && user.isAdmin === true) {
        res.send('Welcome Admin')
    }else{
        res.send('Welcome User')
    }
});

module.exports = router
