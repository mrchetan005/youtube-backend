import { v2 as cloudinary } from "cloudinary";
import fs from 'fs';

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const uploadOnCloudinary = async (localFilePath) => {
    try {
        if (!localFilePath) return;
        const response = await cloudinary.uploader.upload(localFilePath,
            { resource_type: 'auto' });

        console.log('file uploaded on cloudinary', response.url);
        fs.unlinkSync(localFilePath); // remove the locally saved temporary file as upload got failed
        return response;
    } catch (error) {
        fs.unlinkSync(localFilePath); // remove the locally saved temporary file as upload got failed
        console.log(error);
        return null;
    }
}

export { uploadOnCloudinary };