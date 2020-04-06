var express = require('express');
var session = require('express-session');
var bodyParser = require('body-parser');
var path = require('path');
const crypto = require('crypto')
var connection = require('./connect.js').connection
var cors = require('cors');
const rateLimit = require("express-rate-limit")
var sendSMS = require('./send_sms').sendSMS
var passManager = require('./passwords.js')
var MySQLStore = require('express-mysql-session')(session);
const putPass = passManager.putPass;
const comparePass = passManager.comparePass;
const captcha = require('./captcha.js')


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
        callback(null, { origin: true, credentials: true })
    } else {
        callback(new Error('Not allowed by CORS'))
    }
}

const apiLimiter = rateLimit({
    windowMs: 1000 * 60 * 10,
    max: 1000
})

const apiLimiter2 = rateLimit({
    windowMs: 1000 * 60 * 15,
    max: 10
})

const usernameRegex = /^[A-Za-z0-9]{3,30}$/
const messageRegex = /^[A-Za-z0-9 \\\^\-!"£$%&*()#';?.>,<|/`\n€]{1,999}$/
const phoneRegex = /^[+][0-9]{10,15}$/

app.use(apiLimiter)

app.use(session({
    cookie: {
        maxAge: 86400000,
        sameSite: "none"
    },
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: true,
    store: new MySQLStore({}, connection)
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(cors(corsOptions))

app.get('/', function (request, response) {
    console.log("hello")
    response.send("Hello world");
    response.end();
});

function mustBeLoggedIn(req, res, next){
    if ((!req.session.username) || (!req.session.userid)) {
        res.status(401)
        res.send("Please log in")
        res.end()
        return;
    }
    next();
}


app.use('/auth', apiLimiter2)
app.use('/auth', captcha.checkCaptcha)
app.post('/auth', function (request, response) {
    var username = request.body.username || request.session.username;
    console.log("auth requested for user", username);
    var password = request.body.password;
    if (username && password) {
        connection.query('SELECT ID FROM users WHERE username = ?', [username], function (error, results, fields) {
            if (results.length > 0) {
                comparePass(connection, results[0].ID, password, function(success){
                    if (success){
                        console.log("Authorised")
                        console.log(results)
                        request.session.userid = results[0].ID
                        request.session.username = username;
                        response.send("Success!");
                        response.end()
                    } else {
                        console.log("Not authorised")
                        response.status(401)
                        response.send('Incorrect Username and/or Password!');
                        response.end()
                    }
                })
            } else {
                console.log("Not authorised")
                response.status(401)
                response.send('Incorrect Username and/or Password!');
                response.end();
            }
        });
    } else {
        console.log("Bad request")
        response.status(400)
        response.send('Please enter Username and Password!');
        response.end();
    }
});

function setPhone(connection, userid, phone, callback) {
    e = encrypt(phone)
    connection.query("UPDATE users SET PHONE=?, phoneIV=? WHERE ID=?", [
        e.encryptedData, e.iv, userid
    ], callback)
}

app.use('/register', captcha.checkCaptcha)
app.post('/register', function (request, response) {
    console.log("creating account [" + request.body.username + "]");
    if (!request.body.username || !request.body.password) {
        console.log("Bad request")
        response.status(400)
        response.send('Please provide Username and Password');
        response.end();
        return;
    }
    if (!usernameRegex.test(request.body.username)) {
        console.log("Malformed username")
        response.status(400)
        response.send('Usernames should be between 3 and 30 alphanumeric characters');
        response.end();
        return;
    }
    connection.query("SELECT ID FROM users WHERE USERNAME=?", [request.body.username], function (err, res, fields) {
        if (res && res.length > 0) {
            response.status(409) //conflict
            response.send("User already exists")
            response.end()
        }
    })
    // TODO: is password stronk?
    console.log("adding username")
    connection.query("INSERT INTO users (USERNAME) VALUES (?)", [
        request.body.username
    ], function (err, res, fields) {
        if (err) {
            console.log("Failed to create user")
            response.status(500);
            response.send("Failed to create user")
            response.end()
            return;
        }
        connection.query("SELECT ID FROM users WHERE USERNAME=?", [request.body.username], function (err, res, fields) {
            console.log("adding password")
            putPass(connection, res[0].ID, request.body.password, function(err){
                if (!err){
                    addMessage(connection, 1, res[0].ID, "Welcome to the site!")
                    if (request.body.phone && phoneRegex.test(request.body.phone)) {
                        setPhone(connection, res[0].ID, request.body.phone)
                    }
                    console.log("Account created successfully")
                    response.send("Account created")
                    response.end()
                } else {
                    console.log("Password thing failed")
                    connection.query("DELETE FROM users WHERE ID=?", [res[0].ID])
                    response.status(500)
                    response.end()
                }
            })
            
        })
    })
})


app.use('/setphone', apiLimiter2)
app.use('/setphone', mustBeLoggedIn)
app.use('/setphone', captcha.checkCaptcha)
app.post("/setphone", function (request, response) {
    if (!request.body.phone || !phoneRegex.test(request.body.phone)) {
        response.send("Please send a phone number")
        response.status(400) // Bad request
        response.end()
        return;
    }
    setPhone(connection, request.session.userid, request.body.phone, function (err, res, fields) {
        if (err) {
            console.log("Error setting phone number")
            response.send("An error occurred")
            response.status(500) // internal server error
            response.end()
        } else {
            console.log("Phone number successfully saved")
        }
    })
})

app.get('/whoami', function (request, response) {
    console.log("whoareyou? ", request.session.username)
    response.send(JSON.stringify({ username: request.session.username || "none" }));
    response.end();
})


function getMessages(connection, to_id, to_name, callback) {
    connection.query(
        'SELECT users.username, messages.content, messages.time, messages.IV FROM \
        users INNER JOIN messages \
        ON users.ID = messages.from \
        WHERE messages.to = ?', [to_id],
        function (error, results, fields) {
            if (!error) {
                console.log("Found " + results.length + " messages")
                results = results.map(m => {
                    return {
                        from: m.username,
                        to: to_name,
                        content: decrypt(m.IV, m.content),
                        timestamp: m.time,
                    }
                })
                console.log("Processed the messages")
                callback(results)
            } else {
                callback([])
            }
        })
}


app.use('/messages', mustBeLoggedIn)
app.get('/messages', function (request, response) {
    console.log("getting messages for ", request.session.username, " userid ", request.session.userid)
    getMessages(connection, request.session.userid, request.session.username, messages => {
        response.send(JSON.stringify(messages))
        response.end()
    });
})

app.post("/logout", function (request, response) {
    request.session.destroy();
})

app.use('/send', mustBeLoggedIn)
app.use('/send', captcha.checkCaptcha)
app.post("/send", function (request, response) {
    var to_user = request.body.to_user;
    var contents = request.body.content;
    console.log("Sending message from user " + request.session.username + " to user " + to_user)
    if ((!to_user || !contents)) {
        console.log("No recipient or no message")
        response.status(400)
        response.send('Please send the recipient username and the message');
        response.end();
    }
    if (!usernameRegex.test(to_user) || !messageRegex.test(contents)) {
        console.log("Malformed username or message")
        response.status(400)
        response.send('Usernames should be between 3 and 30 alphanumeric characters, \
         messages between 1 and 999 alphanumeric characters and spaces');
        response.end();
    }
    get_id(connection, to_user, to_id => {
        if (to_id === -1) {
            console.log("recipient does not exist")
            response.send("Error finding user")
            response.status(422)
            response.end();
            return;
        }
        addMessage(connection, request.session.userid, to_id, contents,
            function (err) {
                if (err) {
                    console.log("Error saving message")
                    response.send("Error saving message")
                    response.status(500)
                    response.end()
                } else {
                    console.log("Success! Message sent")
                    response.send("Success!")
                    response.end()
                }
            })
    })
})

function get_id(connection, username, callback) {
    connection.query("SELECT ID FROM users WHERE USERNAME=?", [username], function (err, res, fields) {
        if (err || !res || res.length < 1) {
            callback(-1)
        }
        callback(res[0].ID)
    })
}

function addMessage(connection, from_id, to_id, contents, callback) {
    encrypted = encrypt(contents)
    connection.query("INSERT INTO messages (`FROM`, `TO`, `CONTENT`, `IV`, `TIME`) VALUES (?, ?, ?, ?, NOW())",
        [
            from_id,
            to_id,
            encrypted.encryptedData,
            encrypted.iv,
        ], callback)
}


app.use('/sendresetcode', apiLimiter2);
app.use('/sendresetcode', captcha.checkCaptcha)
app.post('/sendresetcode', function (request, response) {
    if (!request.body.username) {
        console.log("password reset failed: no username specified")
        response.status(400) // bad request
        response.send("Please specify a username")
        response.end()
        return;
    }
    get_id(connection, request.body.username, (id) => {
        if (id === -1) {
            response.status(500) // server error
            response.end()
        } else {
            getPhone(connection, id, (err, num) => {
                if (err) {
                    response.status(500) // internal server error
                    response.send("Couldn't find phone number")
                    response.end()
                    return;
                }
                crypto.randomBytes(4, function (ex, buf) {
                    token = buf.toString('hex');
                    putToken(connection, id, token, () => { })
                    sendSMS(num, "Your password reset token is " + token);
                })
                response.send("Reset token sent")
                response.end()
            })
        }
    })
})

function getPhone(connection, userid, callback) {
    connection.query("SELECT PHONE, phoneIV FROM users WHERE ID=?", [userid], function (err, res, fields) {
        if (err || !res || !res.length) {
            console.log("err", err)
            console.log("res", res)
            console.log("Couldn't get phone number")
            callback(new Error(), -1)
        } else {
            if (res[0].PHONE === null){
                callback(null, -1)
                return;
            }
            let num = decrypt(res[0].phoneIV, res[0].PHONE);
            callback(null, num)
        }
    })
}

function putToken(connection, userid, token, callback) {
    let e = encrypt(token)
    connection.query("UPDATE users SET RESET=?, RESET_IV=? WHERE ID=?",
        [e.encryptedData, e.iv, userid], callback)
}

function getToken(connection, userid, callback) {
    connection.query("SELECT RESET, RESET_IV FROM users WHERE ID=?", [userid], function (err, res, fields) {
        if (err) {
            callback(err)
            return;
        }
        console.log("res", res)
        if (err || !res || !res.length || res[0].RESET == "0" || res[0].RESET == null) {
            callback(new Error())
        } else {
            token = decrypt(res[0].RESET_IV, res[0].RESET)
            callback(null, token)
        }
    })
}

app.use('/resetwithcode', apiLimiter2)
app.use('/resetwithcode', captcha.checkCaptcha)
app.post('/resetwithcode', function (req, res) {
    if (!req.body.username || !req.body.resetcode || !req.body.password || !usernameRegex.test(req.body.username)) {
        console.log("Bad request for password reset with code")
        res.status(400) // bad request
        res.send("Please specify username, password and reset code")
        res.end()
        return;
    }
    get_id(connection, req.body.username, id => {
        if (id === -1) {
            res.status(500)
            res.end()
            return;
        } else {
            // get and decrypt code
            getToken(connection, id, function (err, token) {
                if (err) {
                    console.log("Error getting token")
                    res.status(500) // server error
                    res.send("Error")
                    res.end()
                } else {
                    if (token != req.body.resetcode) {
                        console.log("Bad reset token")
                        res.status(401) // unauthorized
                        res.send("Incorrect code")
                        res.end()
                        return;
                    }
                    // all good, set password and delete token
                    putPass(connection, id, req.body.password, function(success){
                        if (success){
                            connection.query("UPDATE users SET RESET=?, RESET_IV=? WHERE ID=?",
                            [0, 0, id],
                            function (err) {
                                if (err) {
                                    console.log("Error updating password")
                                    res.status(500) // server error
                                    res.send("Error")
                                    res.end()
                                } else {
                                    console.log("password reset for user " + req.body.username)
                                    res.send("Success! Password updated")
                                    res.end()
                                }
                            })
                        } else {
                            console.log("Error updating password")
                                    res.status(500) // server error
                                    res.send("Error")
                                    res.end()
                        }
                    })
                }
            })

        }
    })
})

app.use('/reset', apiLimiter2)
app.use('/reset', mustBeLoggedIn)
app.use('/reset', captcha.checkCaptcha)
app.post('/reset', function(request, response){
    if (!request.body.newPassword || !request.body.oldPassword) {
        response.send("Please send old and new password")
        response.status(400) // Bad request
        response.end()
        return;
    }
    comparePass(connection, request.session.userid, request.body.oldPassword, function(correct){
        if (correct){
            putPass(connection, request.session.userid, request.body.newPassword, function (err, res, fields) {
                if (err) {
                    console.log("Error changing password")
                    response.send("An error occurred")
                    response.status(500) // internal server error
                    response.end()
                } else {
                    console.log("Password changed successfully")
                    response.send("Success!")
                    response.end()
                }
            })
        } else {
            response.status(401) // unauthorised
            response.send("Incorrect old password")
            response.end()
        }
    })  
})

app.use('/getphone', apiLimiter2)
app.use('/getphone', mustBeLoggedIn)
app.use('/getphone', captcha.checkCaptcha)
app.post('/getphone', function(request, response){
    if (!request.body.password) {
        response.send("Please send password")
        response.status(400) // Bad request
        response.end()
        return;
    }
    comparePass(connection, request.session.userid, request.body.oldPassword, function(correct){
        if (correct){
            getPhone(connection, request.session.userid, function (err, num) {
                if (err) {
                    console.log("Error getting phone number")
                    response.send("An error occurred")
                    response.status(500) // internal server error
                    response.end()
                } else {
                    console.log("Success getting phone number")
                    response.send(JSON.stringify({phone: num}))
                    response.end()
                }
            })
        } else {
            response.status(401) // unauthorised
            response.send("Incorrect password")
            response.end()
        }
    })  
})

app.get('/dbdump', function (request, response) {
    console.log("Dumping database as json")
    connection.query("SELECT * FROM users", [], function(err, res, fields){
        connection.query("SELECT * FROM messages", [], function(err2, res2, fields2){
            if (err || err2){
                response.status(500) // server error
                response.end()
                return;
            }
            let db = {users: res, messages: res2}
            response.send(JSON.stringify(db))
            response.end()
        })
    })
})

app.listen(process.env.PORT || 5000);