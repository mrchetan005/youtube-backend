import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';

const app = express();

// common middlewares
app
    .use(cors({
        origin: process.env.CORS_ORIGIN,
        credentials: true
    }))
    .use(express.json({ limit: '16kb' }))
    .use(express.urlencoded({ extended: true, limit: '16kb' }))
    .use(express.static('public'))
    .use(cookieParser())
    ;


// routes imports
import userRouter from "./routes/user.routes.js";


// routes handling
app.use('/api/v1/users', userRouter);


export default app;