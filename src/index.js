'use strict'

import express from 'express';
import bodyParser from 'body-parser';
import morgan from 'morgan'
import fs from 'fs'
import {
  LocalStorage
} from 'node-localstorage'
import jsonwebtoken from 'jsonwebtoken';
import {
  createHash,
  getHashes
} from 'crypto'
import {
  join
} from 'path'
import jsonpatch from 'json-patch'
import sharp from 'sharp'

let app = express();
let localStorage = new LocalStorage('./localstorage');

let loggedInstance = {
  tokens: {}
};
let response = {};

const registerNewUser = ({
  username,
  password
}) => {
  let userKey = createHash("sha256").update(username + password).digest("base64")
  let userValue = {
    username,
    password
  };
  localStorage.setItem(`@USER:${userKey}`, JSON.stringify(userValue));
}

const getUser = ({
  username,
  password
}) => {
  let userKey = createHash("sha256").update(username + password).digest("base64");
  let user = JSON.parse(localStorage.getItem(`@USER:${userKey}`))

  return (user !== null && user.username === username && user.password === password) ? user : false
}

app.use(bodyParser.urlencoded({
  extended: false
}));
app.use(bodyParser.json());

app.use(morgan('dev'));

app.get('/', (req, res) => {
  res.send('Hello World');
});

app.post('/api/register-user', (req, res) => {

  let patch = {}

  if (getUser(req.body)) {
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "404",
        message: "This user is registered before.!"
      }
    }
    response = jsonpatch.apply(response, patch)
  } else {
    registerNewUser(req.body)
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "200",
        message: "Signed up successfully.!"
      }
    }
    response = jsonpatch.apply(response, patch)
  }

  res.json(response);
});

app.post('/api/login-user', (req, res) => {
  loggedInstance = getUser(req.body);
  let patch = {}

  if (loggedInstance)
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "200",
        message: "Logged in Successfully!"
      }
    }
  else
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "404",
        message: "This user is not registered!"
      }
    }

  response = jsonpatch.apply(response, patch)
  return res.json(response)

});

app.post('/api/logout-user', (req, res) => {
  let patch = {}

  if (loggedInstance.username !== undefined) {
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "200",
        message: "Logged out Successfully!"
      }
    };
    response = jsonpatch.apply(response, patch);

    patch = {
      "op": "add",
      "path": "/loggedInstance",
      "value": {}
    };
    loggedInstance = jsonpatch.apply(loggedInstance, patch);
  } else {
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "404",
        message: "You have already logged out!"
      }
    };
    response = jsonpatch.apply(response, patch);
  }

  res.json(response);
})

app.get('/api/get/token', (req, res) => {
  let patch = {};
  if (loggedInstance.username) {
    if (!loggedInstance.tokens) {
      patch = {
        "op": "add",
        "path": "/access_token",
        "value": jsonwebtoken.sign({
          username: loggedInstance.username
        }, 'TASK', {
          expiresIn: 24*60*60
        })
      }
      loggedInstance = jsonpatch.apply(loggedInstance, patch);
    }

    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "200",
        access_token: loggedInstance.access_token
      }
    };
    response = jsonpatch.apply(response, patch);

  } else {
    patch = {
      "op": "add",
      "path": "/response",
      "value": {
        code: "200",
        message: 'You are not logged in!.'
      }
    };
    response = jsonpatch.apply(response, patch);
  }

  res.json(response);
})

app.get('/api/list-images', (req, res) => {
  let patch = {}
  jsonwebtoken.verify(req.query.token, 'TASK', (err, decoded) => {
    if (err) {
      patch = {
        "op": "add",
        "path": "/response",
        "value": {
          code: "404",
          message: err.message
        }
      };
      response = jsonpatch.apply(response, patch);
    } else {
      patch = {
        "op": "add",
        "path": "/response",
        "value": {
          code: "200",
          output: res.send(fs.readdirSync(join(__dirname, '../res/')))
        }
      };
      response = jsonpatch.apply(response, patch);
    }

    return res.send(response);
  })
});

app.listen(9000);
