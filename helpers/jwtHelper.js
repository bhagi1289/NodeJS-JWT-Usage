const JWT = require("jsonwebtoken");
const createError = require("http-errors");
const redisClient = require("../helpers/initRedis");
redisClient.connect();

module.exports={
    signAccessToken:(userId)=>{
        return new Promise((resolve, reject)=>{
            const payload = {
                
            };
            const secret = process.env.ACCESS_TOKEN_SECRET;
            const options = {
                expiresIn: "30s",
                issuer: "bhagyaraju.co.in",
                audience: `${userId}`
            }
            JWT.sign(payload, secret, options, (err, token)=>{
                if(err){
                    console.log(err.message);

                    return reject(createError.InternalServerError())
                }
                resolve(token)
            })
        })
    },

    verifyAccessToken:(req, res, next)=>{
        try {
            if(!req.headers['authorization'])
                return next(createError.Unauthorized())
            const authHeader = req.headers['authorization'];
            const bearerToken = authHeader.split(' ');
            const token = bearerToken[1];
            JWT.verify(token, process.env.ACCESS_TOKEN_SECRET, (error, payload)=>{
                if(error){
                    // if(error.name === "JsonWebTokenError"){
                    //     return next(createError.Unauthorized());
                    // }else{
                    //     return next(createError.Unauthorized(error.message));
                    // }
                    const message = error.name === 'JsonWebTokenError'? 'Unauthorized' : error.message;
                    return next(createError.Unauthorized(message));
                }
                req.payload = payload
                next()
            });

        } catch (error) {
           next(createError.Unauthorized()); 
        }
    },

    signRefreshToken: (userId)=>{
        return new Promise((resolve, reject)=>{
            const payload = {
                
            };
            const secret = process.env.REFRESH_TOKEN_SECRET;
            const options = {
                expiresIn: "1y",
                issuer: "bhagyaraju.co.in",
                audience: `${userId}`
            }
            JWT.sign(payload, secret, options, async (err, token)=>{
                if(err){
                    console.log(err.message);

                    return reject(createError.InternalServerError())
                }
                await redisClient.SET(`${userId}`, token, 'EX', 365*24*60*60);
                resolve(token)
            })
        })
    },

    verifyRefreshToken: (refreshToken)=>{

        return new Promise((resolve, reject)=>{
            JWT.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, async(error, payload)=>{
                if(error)
                    return reject(createError.Unauthorized())
                
                const userId = payload.aud;
                let getRefreshToken = await redisClient.GET(`${userId}`);
                if(!getRefreshToken)
                    return reject(createError.InternalServerError());
                
                if(getRefreshToken === refreshToken)
                    return resolve(userId);
                return reject(createError.Unauthorized());
                
            });
        });
    }
}