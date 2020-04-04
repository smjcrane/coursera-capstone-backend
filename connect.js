var config = {
    host: process.env.HOST,
    user: process.env.USER,
    password: process.env.PASS,
    port: process.env.DBPORT,
    database: process.env.DATABASE,
}


var mysql = require('mysql');
var connection = mysql.createConnection(config);

connection.connect(err => {
    if (err) throw err;
    console.log("Connected!");
});

exports.connection = connection;