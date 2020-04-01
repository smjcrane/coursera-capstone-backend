var express = require('express');
var session = require('express-session');
var MemoryStore = require('memorystore')(session)
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto')
var connection = require('./connect.js').connection
var cors = require('cors');

let md5 = (str) => crypto.createHash('md5').update(str).digest("hex")

const frontend_home = 'https://simon-security-capstone.herokuapp.com';
var app = express();

var corsOptions = function (request, callback) {
    origin = request.header("Origin") || "no";
        console.log("request from origin ", origin);
      if (origin.substring(0, frontend_home.length) == frontend_home) {
        callback(null, {origin: true, credentials: true})
      } else {
        callback(new Error('Not allowed by CORS'))
      }
    }
  

app.use(session({
    cookie: {maxAge: 86400000},
    store: new MemoryStore({
        checkPeriod: 86400000
    }),
	secret: 'secr83kcuby4bl7sq5wffdypijaem3oncqet',
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
    console.log(request.session)
	var username = request.body.username;
    var password = request.body.password;
    console.log("check", username+password, md5(username+password));
	if (username && password) {
		connection.query('SELECT * FROM users WHERE username = ? AND pass = ?', [username, md5(username+password)], function(error, results, fields) {
			if (results.length > 0) {
                console.log("Authorised")
                request.session.loggedin = true;
                request.session.userid = results[0].ID
                request.session.username = username;
				response.send("Success!");
			} else {
                console.log("Not authorised")
                response.status(401)
				response.send('Incorrect Username and/or Password!');
			}
			response.end();
		});
	} else {
        console.log("Bad request")
        response.status(400)
		response.send('Please enter Username and Password!');
		response.end();
	}
});

app.get('/whoami', function(request, response){
    console.log("whoareyou? ", request.session.username)
    console.log(request.session)
    response.send(JSON.stringify({username: request.session.username || "none"}));
    response.end();
})

app.get('/messages', function(request, response){
    console.log("getting messages")
    console.log(request.session)
    if((!request.session.username) || (!request.session.userid)){
        response.send("Please log in")
        response.end()
        return;
    }
    console.log("getting messages for ", request.session.username, " userid ", request.session.userid)
    connection.query(
        'SELECT users.username, messages.content, messages.time FROM \
        users INNER JOIN messages \
        ON users.ID = messages.from \
        WHERE messages.to = ?', [request.session.userid], 
        function(error, results, fields){
        if (!error && results.length > 0){
            console.log("Found "+results.length+" messages")
            response.send(JSON.stringify(results))
            response.end()
            return
        } else{
            console.log("Error getting messages")
            response.send("[]")
            response.end()
            return
        }
    })
})

app.post("/logout", function (request, response){
    request.session.destroy();
})

app.listen(process.env.PORT || 5000);
