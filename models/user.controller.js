import { ApiResponse } from "./ApiResponse"
import { ApiError } from "./ApiError"
import {asyncHandler} from "./asyncHandler"
import { User } from "./user.models";
import { UserProfile } from "./userProfile.models";
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

const refreshAccessToken = asyncHandler (async (req, res) => {
    const incomingRefreshToken = req.body.accessToken || req.header.accessToken
    if (!incomingRefreshToken){
        throw new ApiError(402,"unAuthorized Request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken, process.env.ACCESS_TOKEN_SECRET
        )
        const user = await User.findById(decodedToken._id)
        if (!user) {
            throw new ApiError(402, "user does not exists")
        }
        if (!incomingRefreshToken === user.accessToken){
            throw new ApiError(402, "token is incorrect!!! access denied")
        }
        const {accessToken, refreshToken} = generateAccessAndRefreshToken(user._id)
        
       return res
       .status(200)
       .json(
        new ApiResponse(
            200,
            {accessToken, refreshToken},
            "refresh token updated successfully"
        )
       )
    } catch (error) {
        
    }
})

const updatePassword = asyncHandler(async(req, res) => {

    try {
        const {oldPassword, newPassword, confirmPassword} = req.body
        const user = await User.findById(req.user._id)

        if (!user){
            throw new ApiError(402, "user does not exists")
        }

        const checkPassword = bcrypt.compare(oldPassword, user.password )
        if (!checkPassword){
            throw new ApiError (402, "incorrect password")
        }

        if (confirmPassword !== newPassword){
            throw new ApiError(402, "your old and new password does not match")
        }

        user.password = newPassword
       await user.save({validateBeforeSave: false})

       return res
       .status (200)
       .json(
        new ApiResponse (
            200,
            "password is updated successfully"
        )
       )

    } catch (error) {
        throw new ApiError (
            402, "password updation failed.. please try again"
        )
    }
})

const updateEmail = asyncHandler (async (req, res) => {
    const {email, password} = req.body

    try {
        if (!email || !password){
            throw new ApiError (403, "email and password are must required")
        }

        const user = await User.findById(req.user._id)
        if (!user){
            throw new ApiError(401,"user does not exists")
        }
        
        const matchPassword = bcrypt.compare(user.password, password)
        if (!matchPassword){
            throw new ApiError(403, "password does not match")
        }

        if (user.email === email){
            throw new ApiError(403, "email cannot be same as old one")
        }

        const alreadyExistingEmail = await User.findOne(email)
        if(alreadyExistingEmail){
            throw new ApiError(403, "email already exists")
        }

        user.email = email
        await user.save({validateBeforeSave: false})


    } catch (error) {
        throw new ApiError (500, "error while updating email")
    }
})

const updateUsername = asyncHandler (async (req, res) => {
    const {username, password} = req.body

    try {
        if (!username || !password){
            throw new ApiError (402, "username and password is must required")
        }

        const user = await User.findById(req.user._id)
        if (!user){
            throw new ApiError (403, "user does not exists")
        }

        const matchPassword = bcrypt.compare(user.password, password)
        if (!matchPassword){
            throw new ApiError(403, "password does not match")
        }

        if (user.username === username){
            throw new ApiError(403, "username cannot be same as old one")
        }

        const alreadyExistingUsername = await User.findOne(username)
        if (alreadyExistingUsername){
            throw new ApiError(403, "username already exists")
        }

        user.username = user
        await user.save({validateBeforeSave: false})

    } catch (error) {
        throw new ApiError (501, "error while updating username")
    }
})

const updateName = asyncHandler (async (req, res) => {
        try {
            const {name} = req.body
            const user = await User.findById(req.user._id)
            if (!user){
                throw new ApiError (403, "user does not exists")
            }
            if (!name){
                throw new ApiError (402, "please enter new name")
            }
            user.name = name
            await user.save({validateBeforeSave: false})
            return res
            .status(200)
            .json(
                new ApiResponse(
                    200,
                    "name is updated successfully"
                )
            )
            
        } catch (error) {
            throw new ApiError (501, "error while updating name")
        }
})

const updatePhone = asyncHandler (async (req, res) => {
    const {phone} = req.body
    const user = await User.findById(req.user._id)

    if (!user){
        throw new ApiError(402, "user does not exists")
    }
    if (!phone){
        throw new ApiError (401, "please enter phone number first before editing")
    }
    user.phone = phone 
    await user.save({validateBeforeSave: false})

    return res
    .status(201)
    .json(
        new ApiResponse (200, "phone number updated successfully")
    )
})


const updateBio = asyncHandler (async (req, res) => {
    const {bio} = req.body
    const user = await UserProfile.findById(req.user._id)

    if (!user){
        throw new ApiError(402, "user does not exists")
    }
    if (!bio){
        throw new ApiError (401, "please enter bio first before editing")
    }
    user.bio = bio
    await user.save({validateBeforeSave: false})

    return res
    .status(201)
    .json(
        new ApiResponse (200, "bio updated successfully")
    )
})

const updateAddress = asyncHandler (async (req, res) => {

    const {address} = req.body
    const { city, state, postalCode } = address;
    const user = await User.findById(req.user._id)

    if(!user){
        throw new ApiError(402, "user does not exists")
    }

    if (!city || !postalCode || !state){
        throw new ApiError (402, "please enter all details first")
    }
    
    user.address ={
        postalCode,
        city,
        state
    }
    await user.save({validateBeforeSave: false})

    return res
    .status (200)
    .json(
        200 , "address updated successfuly"
    )
})

export {
    registerUser,
    loginUser,
    logoutUser,
    refreshAccessToken,
    updatePassword,
    updateEmail,
    updateUsername,
    updateName,
    updatePhone,
    updateAddress,
    updateBio
}