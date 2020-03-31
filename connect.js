var config = require("./config.json");


var mysql = require('mysql');
var connection = mysql.createConnection(config);

connection.connect(err => {
    if (err) throw err;
    console.log("Connected!");
});

exports.connection = connection;