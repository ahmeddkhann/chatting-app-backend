import { ApiResponse } from "./ApiResponse"
import { ApiError } from "./ApiError"
import {asyncHandler} from "./asyncHandler"
import { User } from "./user.models";
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"


const generateAccessAndRefreshToken = async (userId) => {

    try {
        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken
        await user.save({validateBeforeSave: false})
        return {accessToken, refreshToken}
    } catch (error) {
        throw new ApiError (500, "error while generating access and refresh tokens")
    }
}

const registerUser = asyncHandler(async (req, res) => {
    const { name, email, password, username, address, phone } = req.body;
    if (
        [name, email, password, username, address, phone].some((field) => !field || field.trim() === "")
    ) {
        throw new ApiError(400, "All fields are required");
    }

    const existingUser = await User.findOne({
        $or: [{ username }, { email }]
    });

    if (existingUser) {
        throw new ApiError(409, "Username or email already exists");
    }

    const newUser = new User({
        name,
        email,
        password, 
        username,
        address,
        phone
    });

    await newUser.save();

    const user = await User.findById(newUser._id).select("-password");
    if (!user) {
        throw new ApiError(500, "Error while registering user... try again");
    }

    res.status(201).json({
        message: "User registered successfully",
        user
    });
});

const loginUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;

    if (!email && !username) {
        throw new ApiError(400, "Email or username is required");
    }
    if (!password) {
        throw new ApiError(400, "Password is required");
    }

    const user = await User.findOne({
        $or: [{ email }, { username }]
    });

    if (!user) {
        throw new ApiError(403, "User does not exist! Please provide a valid email or username");
    }

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
        throw new ApiError(401, "Password is incorrect");
    }

    const generatingToken = await generateAccessAndRefreshToken(user._id);
    if (!generatingToken) {
        throw new ApiError(500, "There is an issue in logging in the user");
    }

    return res.status(200).json({
        accessToken: generatingToken.accessToken,
        refreshToken: generatingToken.refreshToken,
        user: {
            id: user._id,
            email: user.email,
            username: user.username,
        }
    });
});

const logoutUser = asyncHandler(async (req, res) => {
    const { email, username, password } = req.body;
    
    if (!email && !username) {
        throw new ApiError(403, "Either username or email is required");
    }
    if (!password) {
        throw new ApiError(403, "Password is required");
    }

    const user = await User.findOne({
        $or: [{ username }, { email }]
    });
    
    if (!user) {
        throw new ApiError(402, "User does not exist");
    }

    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        throw new ApiError(404, "Password is incorrect");
    }

    await User.findByIdAndUpdate(user.id, {
        $unset: {
            accessToken: 1,
        }
    });

    return res.status(200).json({
        status: 201,
        message: "User logged out successfully"
    });
})



export {
    registerUser,
    loginUser,
    logoutUser
}