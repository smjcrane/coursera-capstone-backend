var express = require('express');
var session = require('express-session');
var MemoryStore = require('memorystore')(session)
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto')
var CryptoJS = require("crypto-js");
var connection = require('./connect.js').connection
var cors = require('cors');
const rateLimit = require("express-rate-limit")

let md5 = (str) => crypto.createHash('md5').update(str).digest("hex")
const AES_key = process.env.AES_KEY;
let encrypt = (text) => CryptoJS.AES.encrypt(text, AES_key).toString();
let decrypt = (text) => CryptoJS.AES.decrypt(text, AES_key).toString(CryptoJS.enc.Utf8);

const frontend_home = 'https://simon-security-capstone.herokuapp.com';
var app = express();

const corsOptions = function (request, callback) {
    origin = request.header("Origin") || "no";
    console.log("request from origin ", origin);
    if (origin.substring(0, frontend_home.length) == frontend_home) {
        callback(null, {origin: true, credentials: true})
    } else {
        callback(new Error('Not allowed by CORS'))
    }
}

const apiLimiter = rateLimit({
    windowMs: 1000 * 60 * 10,
    max: 100
})

const apiLimiter2 = rateLimit({
    windowMs: 1000 * 60 * 15,
    max: 10
})

const usernameRegex = /^[A-Za-z0-9_]{3,30}$/
const messageRegex = /^[A-Za-z0-9 ]{1,999}$/
  
app.use(apiLimiter)

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

app.use('/auth', apiLimiter2)

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
            results = results.map(m => {return {
                from: m.username,
                to: request.session.username,
                content: decrypt(m.content),
                timestamp: decrypt(m.time),
            }})
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

app.post("/send", function(request, response){
    var to_user = request.body.to_user;
    var contents = request.body.content;
    console.log("Sending message ["+contents+"] to user "+to_user)
    if((!request.session.username) || (!request.session.userid)){
        response.send("Please log in")
        response.end()
        return;
    }
    if ((!to_user || !contents)){
        console.log("No addressee or no message")
        response.status(400)
		response.send('Please send the addressees username and the message');
        response.end();    
    }
    if (!usernameRegex.test(to_user) || !messageRegex.test(contents)){
        console.log("Malformed username or message")
        response.status(400)
        response.send('Usernames should be between 3 and 30 alphanumeric characters, \
         messages between 1 and 999 alphanumeric characters and spaces');
        response.end();  
    }
    let to_id = -1;
    connection.query("SELECT * FROM users WHERE USERNAME=?", [to_user], function(err, res, fields){
        if (err || !res || res.length < 1){
            response.send("Error finding user")
            response.status(422)
            response.end();
            return;
        }
        to_id = res[0].ID
        connection.query("INSERT INTO messages (`FROM`, `TO`, `CONTENT`) VALUES (?, ?, ?)", 
        [
            request.session.userid,
            to_id,
            encrypt(contents)
        ], function(err, res, fields){
            if (err){
                response.send("Error saving message")
                response.status(500)
                response.end()
            }
        })
    })
})

app.listen(process.env.PORT || 5000);
