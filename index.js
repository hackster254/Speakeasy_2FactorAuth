const express = require('express')
const speakeasy = require('speakeasy')
const uuid = require('uuid')

const bodyParser = require("body-parser");

// to use qr code
const QRCode = require('qrcode')

const {JsonDB } = require('node-json-db')
const { Config }= require('node-json-db/dist/lib/JsonDBConfig')
const app = express()

//Here we are configuring express to use body-parser as middle-ware.
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

//app.use(express.json())
// iniitailize json db
const db = new JsonDB(new Config('authDB', true, false, '/'))

const PORT = process.env.PORT || 5000

app.get('/api', (req, res) => res.json({

    message: 'Welcome to 2 factor auth project'
    })
)

// register user and create temp secret
app.post('/api/register',async (req, res)=> {
    //get id and generate
    const id = uuid.v4()

    try{
      const path = `/user/${id}`;

      const temp_secret = speakeasy.generateSecret();

      // FOR QRCODE TO GENERATE AND STORE
        QRCode.toDataURL(temp_secret.otpauth_url, function (err, data_url) {
        console.log('---QRCODE IS ---/n'+ data_url);
      });

      //qrcode
      const qrcode = await QRCode.toDataURL(temp_secret.otpauth_url)
      // push to db
      db.push(path, { id: id, temp_secret, data_url: qrcode });
      /*
      res.json({
        id,
        secret: temp_secret.base32, // just respond with base32,
        url: `<img src=${qrcode} >`, // url of qrcode
      });
      */
     return res.send(`<h3>TEMP SECRET:  ${temp_secret.base32}</h3> 
     <h3> userID: ${id} </h3> <img src=${qrcode}> `)
    }catch(error) {
        console.log(error)
        res.status(500).json({
            message: 'Error generating secret'
        })
    }

})
// get request to show token registration //NOT WORKING
app.get('/api/register', async(req, res)=> {
    const {id} = await req.body
    console.log(id)
})
// route to verify the token and make secret permanent
app.post('/api/verify',(req, res)=> {
    // from the body pull out token and userId
    const {token, userId} = req.body

    try {
        const path = `/user/${userId}`
        // get use with the id from the path
        const user = db.getData(path)

        // getting base32 from database jsonDb and
        // calling it secret

        const { base32: secret} = user.temp_secret

        // verifying the token
        const verified = speakeasy.totp.verify({
            secret,
            encoding: 'base32',
            token
        });

        if(verified){
            // change temp_secret in our db to secret(permanent)
            db.push(path, {
                id: userId,
                secret: user.temp_secret
            })
            res.json({
                verified: true
            })
        }else {
            res.json({
                verified: false
            })
        }
        
    } catch (error) {

        console.log(error);
        res.status(500).json({
          message: "Error verifying and finding user",
        });
        
    }
})

// route to validate the token and from the permanent secret
app.post("/api/validate", (req, res) => {
  // from the body pull out token and userId
  const { token, userId } = req.body;

  try {
    const path = `/user/${userId}`;
    // get use with the id from the path
    const user = db.getData(path);

    // getting base32 from database jsonDb and
    // calling it secret

    const { base32: secret } = user.secret;

    // verifying the token
    const tokenValidate = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1
    });

    if (tokenValidate) {
      // change temp_secret in our db to secret(permanent)
     
      res.json({
        validated: true,
      });
    } else {
      res.json({
        validated: false,
      });
    }
  } catch (error) {
    console.log(error);
    res.status(500).json({
      message: "Error validating and finding user",
    });
  }
});

app.listen(PORT, () => console.log('server listening on ${PORT}'))