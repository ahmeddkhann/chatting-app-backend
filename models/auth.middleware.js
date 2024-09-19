import { asyncHandler } from "./asyncHandler";
import { ApiError } from "./ApiError";
import { User } from "./user.models";
import jwt from "jsonwebtoken"

export const verifyJWT = asyncHandler(async (req, next) => {
  
    try {
        const token = req.cookies?.accessToken || req.header
        ("Authorization").replace("bearer", "")

        if (!token){
            throw new ApiError(402, "unAuthoroized Request! Token Unavailable")
        }

        const decodedToken = jwt.verify(process.env.ACCESS_TOKEN_SECRET, token)
        if (!decodedToken){
            throw new ApiError(402, "unAuthorized Request! Token verification Failed")
        }

        const user = await User.findById(decodedToken._id)
        if (!user){
            throw new ApiError (402, "user not available")
        }

        req.user = user
        return next()
        
    } catch (error) {
        throw new ApiError(500, "error while verifying JWT token: ", error)
    }
})