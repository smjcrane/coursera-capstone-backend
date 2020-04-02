const accountSid = process.env.TWILIO_SID;
const authToken = process.env.TWILIO_AUTH;
const client = require('twilio')(accountSid, authToken);

function sendSMS(number, message){
    client.messages
  .create({
     body: message,
     from: '+15139724950',
     to: number
   })
  .then(message => console.log("Sent message, sid:", message.sid))
  .catch("Error sending message");
}

exports.sendSMS = sendSMS;