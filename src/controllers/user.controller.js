import jwt from "jsonwebtoken";
import { cookieOptions } from "../constants.js";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { uploadOnCloudinary } from "../utils/cloudinary.js";

const generateAccessAndRefreshTokens = async (user) => {
    try {
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();
        user.refreshToken = refreshToken;
        await user.save({ validateBeforeSave: false }, { new: true });
        return { accessToken, refreshToken };
    } catch (error) {
        throw new ApiError(500, "Something went wrong while generating refresh and access token");
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { email, password, fullName, username } = req.body;
    Object.entries({ username, email, fullName, password }).forEach(([field, value]) => {
        if (!value?.trim()) {
            throw new ApiError(400, `${field} is required`);
        }
    })

    const existingUser = await User.findOne({
        $or: [{ email }, { username }]
    });

    if (existingUser) {
        throw new ApiError(409, `Email or username already exists`);
    }

    const avatarLocalPath = req?.files?.avatar?.[0]?.path
    const coverImageLocalPath = req?.files?.coverImage?.[0]?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "avatar is required")
    }


    const avatar = await uploadOnCloudinary(avatarLocalPath);
    const coverImage = await uploadOnCloudinary(coverImageLocalPath);

    if (!avatar) {
        throw new ApiError(400, "avatar is required")
    }

    const newUser = await User.create({
        fullName, email, password,
        username: username.toLowerCase(),
        avatar: avatar.url,
        coverImage: coverImage?.url || ""
    });

    const { password: _, ...userDetails } = newUser['_doc'];

    return res.status(201).json(new ApiResponse(201, { user: userDetails }, 'User registered successfully'))
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;

    if (!username && !email) {
        throw new ApiError(400, "Username or Email is required");
    }

    if (!password) {
        throw new ApiError(400, "Password is required");
    }

    const user = await User.findOne({
        $or: [{ email }, { username }]
    });

    if (!user) {
        throw new ApiError(404, 'Invalid user credentials')
    }
    // compare passwords
    const isPasswordMatch = await user.isPasswordValid(password);
    if (!isPasswordMatch) {
        throw new ApiError(401, 'Invalid user credentials')
    }
    // create and assign a token to the user
    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user);

    // excluding password and refresh token from user to send response
    delete user.password;
    delete user.refreshToken;
    const { password: _, refreshToken: __, ...userDetails } = user['_doc'];

    return res
        .status(200)
        .cookie("accessToken", accessToken, cookieOptions)
        .cookie("refreshToken", refreshToken, cookieOptions)
        .json(new ApiResponse(200, { accessToken, refreshToken, user: userDetails }, 'User logged in successfully'));

});

const logoutUser = asyncHandler(async (req, res) => {
    const userId = req.user._id;
    await User.findByIdAndUpdate(userId, {
        $unset: { refreshToken: 1 }
    }, { new: true });

    return res
        .status(200)
        .clearCookie('accessToken', cookieOptions)
        .clearCookie('refreshToken', cookieOptions)
        .json(new ApiResponse(200, {}, 'User logged out successfully'));
});

const refreshAccessToken = asyncHandler(async (req, res) => {
    const incomingRefreshToken = req.cookies?.refreshToken || req.body?.refreshToken;

    if (!incomingRefreshToken) {
        throw new ApiError(401, 'Unauthorized request');
    }

    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);

    if (!decodedToken) {
        throw new ApiError(401, "Expired or invalid token");
    }

    const user = await User.findById(decodedToken._id);
    if (!user) {
        throw new ApiError(401, "Invalid refresh token");
    }
    // check if the user's current refresh token is valid
    if (user?.refreshToken !== incomingRefreshToken) {
        throw new ApiError(401, "Refresh token is expired");
    }

    const { accessToken, refreshToken } = await generateAccessAndRefreshTokens(user);

    return res
        .status(200)
        .cookie('accessToken', accessToken, cookieOptions)
        .cookie('refreshToken', refreshToken, cookieOptions)
        .json(new ApiResponse(200, { accessToken, refreshToken }, 'Access token refreshed'));
});

const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
        throw new ApiError(400, "Missing fields");
    }
    const user = req.user;

    const isPasswordMatch = await user.isPasswordValid(oldPassword);
    if (!isPasswordMatch) {
        throw new ApiError(403, "Incorrect old password");
    }

    user.password = newPassword;
    await user.save({ validateBeforeSave: false });
    return res
        .status(200)
        .json(new ApiResponse(200, null, "Password successfully changed"));
});

const getCurrentUser = asyncHandler(async (req, res) => {
    return res.status(200).json(new ApiResponse(200, req.user, 'Current user fetched successfully'));
});

const updateAccountDetails = asyncHandler(async (req, res) => {
    const { fullName, email } = req.body;

    if (!fullName && !email) {
        throw new ApiError(400, "Please provide either fullName or email");
    }

    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set: { fullName, email }
    }, { new: true }).select('-password -refreshToken');

    return res
        .status(200)
        .json(new ApiResponse(200, user,
            `Account details updated successfully`));
});

const updateUserAvatar = asyncHandler(async (req, res) => {
    const avatarLocalPath = req.file?.path;

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is missing");
    }

    const avatar = await uploadOnCloudinary(avatarLocalPath);
    if (!avatar?.url) {
        throw new ApiError(500, "Failed to save image on cloudinary");
    }

    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set: { avatar: avatar.url }
    }, { new: true }).select('-password -refreshToken');

    return res
        .status(200)
        .json(new ApiResponse(200, user, 'Avatar updated successfully'));
});

const updateUserCoverImage = asyncHandler(async (req, res) => {
    const coverImageLocalPath = req.file?.path;

    if (!coverImageLocalPath) {
        throw new ApiError(400, "Cover Image file is missing");
    }

    const coverImage = await uploadOnCloudinary(coverImageLocalPath);
    if (!coverImage?.url) {
        throw new ApiError(500, "Failed to save image on cloudinary");
    }

    const user = await User.findByIdAndUpdate(req.user?._id, {
        $set: { coverImage: coverImage.url }
    }, { new: true }).select('-password -refreshToken');

    return res
        .status(200)
        .json(new ApiResponse(200, user, 'Cover Image updated successfully'));
});

const getUserChannelProfile = asyncHandler(async (req, res) => {
    const { username } = req.params;
    if (!username?.trim()) {
        throw new ApiError(400, "Username is missing");
    }
    let channel = await User.aggregate([
        { $match: { username: username?.toLowerCase() } },
        {
            $lookup: {
                from: 'subscriptions',
                localField: '_id',
                foreignField: 'channel',
                as: 'subscribers'
            }
        },
        {
            $lookup: {
                from: 'Subscription',
                localField: '_id',
                foreignField: 'subscriber',
                as: 'subscribedTo'
            }
        },
        {
            $addFields: {
                subscribersCount: {
                    $size: '$subscribers'
                },
                channelsSubscribedToCount: {
                    $size: '$subscribedTo'
                },
                isSubscribed: {
                    $cond: {
                        if: {
                            $in: [req.user?._id, '$subscribers.subscriber']
                        },
                        then: true,
                        else: false
                    }
                }
            }
        },
        {
            $project: {
                fullName: 1, username: 1, email: 1,
                isSubscribed: 1, subscribersCount: 1,
                channelsSubscribedToCount: 1,
                avatar: 1,
                coverImage: 1,
                createdAt: 1, updatedAt: 1
            }
        }
    ]);

    if (!channel?.length) {
        throw new ApiError(404, `Channel not found.`);
    }

    return res
        .status(200)
        .json(new ApiResponse(200, channel[0], 'User channel fetched successfully'));
});

const getUserWatchHistory = asyncHandler(async (req, res) => {
    const user = await User.aggregate([
        {
            $match: {
                _id: req.user._id
            }
        },
        {
            $lookup: {
                from: 'videos',
                localField: 'watchHistory',
                foreignField: '_id',
                as: 'watchHistory',
                pipeline: [
                    {
                        $lookup: {
                            from: 'users',
                            localField: 'owner',
                            foreignField: '_id',
                            as: 'owner',
                            pipeline: [
                                {
                                    $project: {
                                        fullName: 1,
                                        username: 1,
                                        avatar: 1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields: {
                            owner: {
                                // $arrayElemAt: ['$owner', 0]
                                $first: '$owner'
                            }
                        }
                    }
                ]
            }
        }
    ]);

    return res
        .status(200)
        .json(new ApiResponse(200, user[0].watchHistory, "User watch history fetched successfully"));
});

export { registerUser, loginUser, logoutUser, refreshAccessToken, changeCurrentPassword, getCurrentUser, updateAccountDetails, updateUserAvatar, updateUserCoverImage, getUserChannelProfile, getUserWatchHistory };

