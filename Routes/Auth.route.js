const express = require("express");
const createError = require("http-errors");
const { signAccessToken, signRefreshToken, verifyRefreshToken } = require("../helpers/jwtHelper");
const { authSchema } = require("../helpers/validationSchema");
const router = express.Router();
const User = require("../Models/User.model");
const redisClient = require("../helpers/initRedis");

router.post('/register', async(req, res, next)=>{

    try {
        // const {email, password} = req.body;
        const result = await authSchema.validateAsync(req.body);

        const userExists = await User.findOne({email:result.email});
        if(userExists)
            throw createError.Conflict(`${result.email} is already been registered`);

        const user = new User(result);
        const savedUser = await user.save();
        const accessToken = await signAccessToken(savedUser._id);
        const refreshToken = await signRefreshToken(savedUser._id);
        res.send({accessToken, refreshToken});

    } catch (error) {
        if(error.isJoi){ 
            error.status = 422
        }
        next(error);
    }
})

router.post('/login', async(req, res, next)=>{

    try {
        const result = await authSchema.validateAsync(req.body);
        const user = await User.findOne({email:result.email});
        if(!user)
            throw createError.NotFound("User not registered");

        const isMatch = await user.isValidPassword(result.password);
        if(!isMatch)
            throw createError.Unauthorized('Username/Password not valid');
        
        const accessToken = await signAccessToken(user._id);
        const refreshToken = await signRefreshToken(user._id);

        res.send({accessToken, refreshToken});
    } catch (error) {
        if(error.isJoi)
            return next(createError.BadRequest("Invalid Username/Password"));
        next(error);
    }
})

router.post('/refresh-token', async(req, res, next)=>{
    try {
        const { refreshToken } = req.body;
        if(!refreshToken)
            throw createError.BadRequest()
        
       const userId = await verifyRefreshToken(refreshToken);

       const accessToken = await signAccessToken(userId);
       const newRefreshToken = await signRefreshToken(userId);

        res.send({accessToken, refreshToken:newRefreshToken});
    } catch (error) {
        next(error);
    }
})

router.delete('/logout', async(req, res, next)=>{

    try {
        const { refreshToken } = req.body;
        if(!refreshToken)
            throw createError.BadRequest();
        const userId = await verifyRefreshToken(refreshToken);
        let data = await redisClient.DEL(`${userId}`);
        if(!data){
             console.log("Error while deleting refresh token")
             throw createError.InternalServerError()
        }else{
            console.log( data)
            res.sendStatus(204);
        }

    } catch (error) {
        next(error)
    }
})

module.exports = router;