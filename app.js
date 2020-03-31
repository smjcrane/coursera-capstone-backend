var express = require('express');
var session = require('express-session');
var MemoryStore = require('memorystore')(session)
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto')
var connection = require('./connect.js').connection
var cors = require('cors');

let md5 = (str) => crypto.createHash('md5').update(str).digest("hex")

var app = express();

var corsOptions = {
    origin: function (origin, callback) {
        console.log("request from origin ", origin);
      if (origin == 'https://simon-security-capstone.herokuapp.com') {
        callback(null, true)
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    }
  }

app.use(session({
    cookie: {maxAge: 86400000},
    store: new MemoryStore({
        checkPeriod: 86400000
    }),
	secret: 'secret',
	resave: true,
	saveUninitialized: true
}));
app.use(bodyParser.urlencoded({extended : true}));
app.use(bodyParser.json());
app.use(cors(corsOptions))

app.get('/', function(request, response) {
    console.log("hello")
    response.send("Hello world");
    response.end();
});

app.post('/auth', function(request, response) {
    console.log("auth requested for user  ", request.body.username);
	var username = request.body.username;
	var password = request.body.password;
	if (username && password) {
		connection.query('SELECT * FROM users WHERE username = ? AND pass = ?', [username, md5(password)], function(error, results, fields) {
			if (results.length > 0) {
                console.log("Authorised")
				request.session.loggedin = true;
				request.session.username = username;
				response.redirect('/');
			} else {
                console.log("Not authorised")
				response.send('Incorrect Username and/or Password!');
			}			
			response.end();
		});
	} else {
        console.log("Bad request")
		response.send('Please enter Username and Password!');
		response.end();
	}
});

app.get('/home', function(request, response) {
    console.log("getting home")
	if (request.session.loggedin) {
		response.send('Welcome back, ' + request.session.username + '!');
	} else {
		response.send('Please login to view this page!');
	}
	response.end();
});

app.listen(process.env.PORT || 5000);