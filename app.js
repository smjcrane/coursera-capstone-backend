var express = require('express');
var session = require('express-session');
var MemoryStore = require('memorystore')(session)
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto')
var connection = require('./connect.js').connection
var cors = require('cors');
const rateLimit = require("express-rate-limit")
var sendSMS = require('./send_sms').sendSMS


let md5 = (str) => crypto.createHash('md5').update(str).digest("hex")

const AES_key = Buffer.from(process.env.AES_KEY, "hex");

function encrypt(text) {
    let iv = crypto.randomBytes(16)
    let cipher = crypto.createCipheriv('aes-256-cbc', AES_key, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { iv: iv.toString('hex'), encryptedData: encrypted.toString('hex') };
}
   
function decrypt(iv, text) {
    iv = Buffer.from(iv, 'hex');
    let encryptedText = Buffer.from(text, 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', AES_key, iv);
    let decrypted = decipher.update(encryptedText);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted.toString();
}

const frontend_home = 'https://simon-security-capstone.herokuapp.com';
var app = express();

const corsOptions = function (request, callback) {
    origin = request.header("Origin") || "no";
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

const usernameRegex = /^[A-Za-z0-9]{3,30}$/
const messageRegex = /^[A-Za-z0-9 \\\^\-!"£$%&*()#';?.>,<|/`\n€]{1,999}$/
  
app.use(apiLimiter)

app.use(session({
    cookie: {
        maxAge: 86400000,
        secure: true,
        sameSite: "none"
    },
    store: new MemoryStore({
        checkPeriod: 86400000
    }),
	secret: process.env.SESSION_SECRET,
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
	var username = request.body.username;
    var password = request.body.password;
	if (username && password) {
		connection.query('SELECT ID FROM users WHERE username = ? AND pass = ?', [username, md5(username+password)], function(error, results, fields) {
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

function setPhone(connection, userid, phone, callback){
    e = encrypt(phone)
    connection.query("UPDATE users SET PHONE=?, phoneIV=? WHERE ID=?", [
        e.encryptedData, e.iv, userid
    ], callback)
}

app.post('/register', function(request, response){
    console.log("creating account ["+request.body.username+"]");
    if (!request.body.username || !request.body.password){
        console.log("Bad request")
        response.status(400)
		response.send('Please provide Username and Password');
        response.end();
        return;
    }
    if (!usernameRegex.test(request.body.username)){
        console.log("Malformed username")
        response.status(400)
        response.send('Usernames should be between 3 and 30 alphanumeric characters');
        response.end(); 
        return;
    }
    connection.query("SELECT ID FROM users WHERE USERNAME=?", [request.body.username], function(err, res, fields){
        if (res && res.length > 0){
            response.status(409) //conflict
            response.send("User already exists")
            response.end()
        }
    })
    // TODO: is password stronk?
    connection.query("INSERT INTO users (USERNAME, PASS) VALUES (?, ?); SELECT LAST_INSERT_ID();", [
        request.body.username,
        md5(request.body.username+request.body.password)
    ], function(err, res, fields){
        if (err){
            console.log("Failed to create user")
            response.status(500);
            response.send("Failed to create user")
            response.end()
            return;
        }
        addMessage(connection, 1, res[0].ID, "Welcome to the site!")
        if (request.body.phone){
            setPhone(connection, res[0].ID, request.body.phone)
        }
        console.log("Account created successfully")
        response.send("Account created")
        response.end()
    })
})

app.get('/whoami', function(request, response){
    console.log("whoareyou? ", request.session.username)
    response.send(JSON.stringify({username: request.session.username || "none"}));
    response.end();
})


function getMessages(connection, to_id){
    connection.query(
        'SELECT users.username, messages.content, messages.time, messages.IV FROM \
        users INNER JOIN messages \
        ON users.ID = messages.from \
        WHERE messages.to = ?', [to_id], 
        function(error, results, fields){
        if (!error){
            console.log("Found "+results.length+" messages")
            results = results.map(m => {return {
                from: m.username,
                to: request.session.username,
                content: decrypt(m.IV, m.content),
                timestamp: m.time,
            }})
            return results
        } else{
            return []
        }
    })
}

app.get('/messages', function(request, response){
    if((!request.session.username) || (!request.session.userid)){
        response.send("Please log in")
        response.end()
        return;
    }
    console.log("getting messages for ", request.session.username, " userid ", request.session.userid)
    messages = getMessages(connection, request.session.userid);
    response.send(messages)
    response.end()
})

app.post("/logout", function (request, response){
    request.session.destroy();
})

app.post("/send", function(request, response){
    var to_user = request.body.to_user;
    var contents = request.body.content;
    console.log("Sending message from user "+request.session.username+" to user "+to_user)
    if((!request.session.username) || (!request.session.userid)){
        console.log("send failed: not logged in")
        response.send("Please log in")
        response.end()
        return;
    }
    if ((!to_user || !contents)){
        console.log("No recipient or no message")
        response.status(400)
		response.send('Please send the recipient username and the message');
        response.end();    
    }
    if (!usernameRegex.test(to_user) || !messageRegex.test(contents)){
        console.log("Malformed username or message")
        response.status(400)
        response.send('Usernames should be between 3 and 30 alphanumeric characters, \
         messages between 1 and 999 alphanumeric characters and spaces');
        response.end();  
    }
    let to_id = get_id(connection, to_user);
    if (to_id === -1){
        console.log("recipient does not exist")
            response.send("Error finding user")
            response.status(422)
            response.end();
            return;
    }
    addMessage(connection, request.session.userid, to_id, contents,
     function(err){
        if (err){
            console.log("Error saving message")
            response.send("Error saving message")
            response.status(500)
            response.end()
        } else{
            console.log("Success! Message sent")
            response.send("Success!")
            response.end()
        }
    })
})

function get_id(connection, username){
    connection.query("SELECT ID FROM users WHERE USERNAME=?", [username], function(err, res, fields){
        if (err || !res || res.length < 1){
            return -1
        }
        return res[0].ID
    })
}

function addMessage(connection, from_id, to_id, contents, callback){
    encrypted = encrypt(contents)
    connection.query("INSERT INTO messages (`FROM`, `TO`, `CONTENT`, `IV`, `TIME`) VALUES (?, ?, ?, ?, ?)", 
    [
        from_id,
        to_id,
        encrypted.encryptedData,
        encrypted.iv,
        new Date().getTime(),
    ], callback)
}

app.post('/sendresetcode', function(req, res){
    // check if logged in
    if (!request.session.username){
        console.log("password reset failed: not logged in")
        response.send("Please log in")
        response.end()
        return;
    }
    getPhone(num => {
    crypto.randomBytes(4, function(ex, buf) {
        token = buf.toString('hex');
        putToken(connection, request.session.userid)
        sendSMS("+"+num, "Your password reset token is "+token);
    })
})

function getPhone(connection, userid, callback){
    connection.query("SELECT PHONE, phoneIV FROM users WHERE ID=?", [userid], function(err, res, fields){
        if (err || !res || !res.length){
            throw new Error("Couldn't get phone number")
        } else {
            let num = decrypt(res[0].phoneIV, res[0].PHONE);
            callback(num)
        }
    })
}

function putToken(connection, userid, token, callback){
    let e = encrypt(token)
    connection.query("UPDATE users SET RESET=?, RESET_IV=? WHERE ID=?", 
    [e.encryptedData, e.iv, userid], callback)
}

app.listen(process.env.PORT || 5000);