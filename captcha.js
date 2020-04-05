const secret = process.env.CAPTCHA_SECRET;
const fetch = require('node-fetch');

function verify(token){
    return fetch(" https://www.google.com/recaptcha/api/siteverify?secret="+secret+"&response="+token, {
        method: "post",
        headers: {'Content-Type': 'application/x-www-form-urlencoded'},
    }).then(res=>res.json())
}

function checkCaptcha(req, res, next){
    if (!req.body.token){
        console.log("No captcha token sent")
        res.status(400)
        res.send()
        res.end()
    } else {
        verify(req.body.token)
        .then(v=>{
            if (v.score < 0.5){
                // probably a bot
                console.log("Captcha token score: "+v.score+", access denied")
                res.status(400)
                res.send()
                res.end()
            } else {
                next()
            }
        })
    }
}

exports.checkCaptcha = checkCaptcha;