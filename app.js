const express = require("express");
const morgan = require("morgan");
const createError = require("http-errors");
require("dotenv").config();
require("./helpers/initMongoDB");

const AuthRoute = require("./Routes/Auth.route");
const { verifyAccessToken } = require("./helpers/jwtHelper");

const app = express();
app.use(express.json());
app.use(morgan('dev'));
app.use(express.urlencoded({extended:true}))

const PORT = process.env.PORT || 3000;

app.get('/',verifyAccessToken, async(req, res, next)=>{
    res.send("Hello from express.")
});

app.use('/auth', AuthRoute);

app.use(async(req, res, next)=>{
    // const error = new Error("Not Found");
    // error.status=404;
    // next(error);
    next(createError.NotFound("This route doesn't exist"));
});

app.use((error, req, res, next)=>{

    res.status(error.status || 500);
    res.send({
        error:{
            status:error.status || 500,
            message: error.message,
        }
    })
});

app.listen(PORT, ()=>{
    console.log(`Server is running on ${PORT}`);
})
