import { ApiResponse } from "./ApiResponse"
import { ApiError } from "./ApiError"
import {asyncHandler} from "./asyncHandler"
import { User } from "./user.models";

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

export {
    registerUser
}