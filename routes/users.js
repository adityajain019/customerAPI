const errors = require('restify-errors');
const bcrypt = require('bcryptjs');
const User = require('../models/User');
const auth = require('../auth');
const jwt = require('jsonwebtoken');
const config = require('../config')
// const 

module.exports = server => {

    //  Register User
    server.post('/register', (req, res, next) => {
        const { email, password } = req.body;

        const user = new User({
            email, password
        })

        bcrypt.genSalt(10, (err, salt) => {
            bcrypt.hash(user.password, salt, async (err, hash) => {
                //  Hash password
                user.password = hash;
                //  User save here
                try {
                    const newUser = await user.save();
                    res.send(201);
                    next();
                } catch (err) {
                    return next(new errors.InternalError(err.message));
                }
            })
        })
    })

    //  Authenticate User
    server.post('/auth', async (req, res, next) => {
        const { email, password } = req.body;

        try {
            //  Authenticate User here
            const user = await auth.authenticate(email, password)

            //  Create a token
            const token = jwt.sign(user.toJSON(), config.JWT_SECRET, {
                expiresIn: '15m'
            })

            const { iat, exp } = jwt.decode(token);
            //  Respond along with token
            res.send({ iat, exp, token });
            next();
        } catch (err) {
            //  Auth failed
            return next(new errors.UnauthorizedError(err));
        }
    })
}