import express from "express";
import dotenv from 'dotenv'
dotenv.config();
import bodyParser from "body-parser";
import mongoose from "mongoose";
// import encrypt from "mongoose-encryption";  //level 2 encryption
// import md5 from 'md5'
import ejs from 'ejs'
// import bcrypt from 'bcrypt'
import session from 'express-session'
import passport from 'passport'
import passportLocalMongoose from 'passport-local-mongoose'
import {Strategy as GoogleStrategy} from 'passport-google-oauth20'
import findOrCreate from 'mongoose-findorcreate'
const saltRounds = 10;
const app = express();

app.use(express.static('public')); // for rendering dynamic pages
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended: true})); //to get body of data that is entered and tap into it 
app.use(session({
    secret: "mySecret",
    resave: false,
    saveUninitialized: false
})); //session started
app.use(passport.initialize()); //starting passport
app.use(passport.session()); //starting session with passport
mongoose.set('strictQuery', true) // to remove deprecation warning

//connection with database
mongoose.connect(`mongodb+srv://yashgarg:${process.env.PASSWORD}@cluster0.fhdwxom.mongodb.net/userDB?retryWrites=true&w=majority`, (err) =>{
    if(err){
        res.send(`Something went wrong: ${err}`);
    }
    console.log('db connected');
});

//defining user schema
const userSchema = new mongoose.Schema (
    {email: String,
    password: String,
    googleId: String,
    secret: String},
    {timestamps: {
        createdAt: 'created_at', // Use `created_at` to store the created date
        updatedAt: 'updated_at' // and `updated_at` to store the last updated date
    }}
);

//for passport local mongoose
userSchema.plugin(passportLocalMongoose);

//creating the findOrCreate function for google oauth strategy
userSchema.plugin(findOrCreate);

//encryption - level 2
// userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });
//encryption - level 2

//creating a mongoose db model with User as an instance
const User = mongoose.model('Users', userSchema);

//creating a strategy with User instance
passport.use(User.createStrategy());

//turn data into cookie
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
}); 

//turn cookie into data
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
}); 

//oauth2 google strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:4000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      console.log(profile); //for checking profile details
      return cb(err, user);
    });
  }
));
//oauth2 google strategy

///////////////////////////ALL THE ROUTES //////////////////////////////////

////////////////////////////////////////////////////////////////////////////
app.get('/', (req, res) => {
    res.render('home.ejs');
});
///////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////
//for login and register via oauth
//this opens the page with all your google ids
app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);

//for redirecting them back to secrets or login in error case
app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////
app.route('/login')
.get((req, res) => {
    res.render('login.ejs')
})
.post((req, res) =>{
   //level 3 - hashing
//    User.findOne({email: req.body.username }, (err, foundUser) =>{
//       if(err){
//         res.send(err);
//       } else{
//         if(foundUser){
//             bcrypt.compare(req.body.password, foundUser.password,(err, result) => {
//                 if(result === true){
//                     res.render('secrets.ejs')
//                 }
//                 res.send(`Something went wrong: ${err}`)
//             });
//         } 
//       }
//    })

    const user = new User({
        username : req.body.username,
        password: req.body.password
    }) 
    req.login(user, function(err) {
        if (err) {
            console.log(err);
        }
        //authentication via passport
        passport.authenticate('local')(req, res, () => {
            res.redirect('/secrets');
         })
      })
});
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////
app.route('/register')
.get((req, res) => {
    res.render('register.ejs');
})
.post((req, res) => {
//  bcrypt.hash(req.body.password, saltRounds)
//  .then(function(hash) {
//     const newUser = new User({
//         email: req.body.username,
//         password: hash 
//     });
//     newUser.save(() =>{
//         res.render('secrets.ejs');
//     })
//  })
//  .catch((err) => res.send(`Something went wrong: ${err}`))

   User.register({username: req.body.username}, req.body.password, (err, userData) =>{
     if(err){
        console.log(err);
     }
     //authentication via passport
     passport.authenticate('local')(req, res, () => {
        res.redirect('/secrets')
     })
   } )
});
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////
app.get('/secrets', (req, res) =>{
//    if(req.isAuthenticated){
//     return res.render('secrets.ejs')
//    }
//    res.redirect('/login')

   User.find({'secert': {$ne : null}}, (err, foundUsers) =>{
    if(err){
        console.log(err)
    }else{
        //userWithScrets is an object with all the secrets of users in the database
        if(foundUsers){
            res.render('secrets.ejs', {usersWithSecrets: foundUsers});
        }
    }
   })
}); 
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////
app.get('/logout', (req, res) => {
    req.logout((err) =>{
        if(err){
            console.log(err)
        }
        res.redirect('/')
    });
});
///////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////
app.route('/submit')
.get((req, res) =>{
    //checking whether the user is loggeg in or not
    if(req.isAuthenticated){
        return res.render('submit.ejs')
    }
    res.redirect('/login')
})
.post((req, res) =>{
    console.log(req.body.secret)
    console.log(req.user);
    User.findById(req.user.id, (err, foundUser) =>{
        console.log(foundUser);
        if(err){
            console.log(err);
        }else{
            if(foundUser){
                foundUser.secret = req.body.secret;
                foundUser.save(() =>{
                    res.redirect('/secrets')

                })
            }
        }
    })
});
///////////////////////////////////////////////////////////////////////////


app.listen(4000, () =>{
    console.log('listening on 4000')
});


