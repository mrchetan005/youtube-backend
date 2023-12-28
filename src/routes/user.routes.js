import { Router } from "express";
import { changeCurrentPassword, getCurrentUser, getUserChannelProfile, getUserWatchHistory, loginUser, logoutUser, refreshAccessToken, registerUser, updateAccountDetails, updateUserAvatar, updateUserCoverImage } from "../controllers/user.controller.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middleware.js";

const router = Router();

router.route('/register')
    .post(upload.fields([
        { name: 'avatar', maxCount: 1 },
        { name: 'coverImage', maxCount: 1 }
    ]), registerUser)

router.route('/login').post(loginUser);
router.route('/refreshToken').post(refreshAccessToken);

// authorized routes
router.use(verifyJWT);

router.route('/logout').post(logoutUser);
router.route('/changePassword').post(changeCurrentPassword);
router.route('/currentUser').get(getCurrentUser);
router.route('/updateAccount').patch(updateAccountDetails);
router.route('/updateAvatar').patch(upload.single('avatar'), updateUserAvatar);
router.route('/updateCoverImage').patch(upload.single('coverImage'), updateUserCoverImage);
router.route('/channel/:username').get(getUserChannelProfile);
router.route('/watchHistory').get(getUserWatchHistory);


export default router;
