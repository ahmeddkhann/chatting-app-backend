import { Router } from "express";
import {verifyJWT} from "./auth.middleware"
import {
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
} from "./user.controller"

const router = Router()

router.route("/signup").post(registerUser)
router.route("/login").post(verifyJWT, loginUser)
router.route("/logout").post(verifyJWT, logoutUser)
router.route("/refreshToken").get(verifyJWT, refreshAccessToken) // optional (i did it without any purpose)
router.route("/updatePassword").patch(verifyJWT, updatePassword)
router.route("/updateEmail").patch(verifyJWT, updateEmail)
router.route("/updateUsername").patch(verifyJWT, updateUsername)
router.route("/updateName").patch(verifyJWT, updateName)
router.route("/updatePhone").patch(verifyJWT, updatePhone)
router.route("/updateBio").patch(verifyJWT, updateBio)
router.route("/updateAddress").patch(verifyJWT, updateAddress)
