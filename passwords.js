const crypto = require('crypto')

const iterations = 10;
const keylen = 20;

function putPass(connection, userid, password, callback){
    var salt = crypto.randomBytes(32).toString('base64');
    crypto.pbkdf2(password, salt, iterations, keylen, 'sha512', function(err, bcryptedPassword) {
                        let hash = (bcryptedPassword.toString('base64'));
                        connection.query("UPDATE users SET PASS=?, salt=? WHERE ID=?",
                        [hash, salt, userid], callback)
                    });
}

function comparePass(connection, userid, password, callback){
    connection.query("SELECT PASS, salt FROM users WHERE ID=?", [userid], function(err, res, fields){
        if (err || !res || !res.length){
            callback (false)
        } else {
            crypto.pbkdf2(password, res[0].salt, iterations, keylen, 'sha512',function(err, bcryptedPassword) {
                let hash = (bcryptedPassword.toString('base64'));
                console.log("hash", hash)
                callback(hash === res[0].PASS)
            });
        }
    })
}

exports.putPass = putPass
exports.comparePass = comparePass