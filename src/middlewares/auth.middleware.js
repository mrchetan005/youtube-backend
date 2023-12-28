import jwt from 'jsonwebtoken';
import { asyncHandler } from '../utils/asyncHandler.js';
import { ApiError } from '../utils/ApiError.js';
import { User } from '../models/user.model.js';

const verifyJWT = asyncHandler(async (req, _, next) => {
    const token = req.cookies?.accessToken || (req.header?.['Authorization'] || req.header?.['authorization'])?.replace('Bearer ', '');

    if (!token) {
        throw new ApiError(401, 'Unauthorized request');
    }
    try {
        const decodedTokenInfo = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

        const user = await User.findById(decodedTokenInfo?._id).select('-refreshToken');

        if (!user) {
            throw new ApiError(401, 'Invalid Access Token');
        }
        req.user = user;
        next();
    } catch (error) {
        throw new ApiError(401, error?.message || 'Invalid Access Token');

    }

});

export { verifyJWT };