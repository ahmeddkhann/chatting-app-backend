import mongoose, {Schema} from "mongoose"
const userProfileSchema = new Schema ({
    user: {
        type: Schema.Types.ObjectId,
        ref: 'User',
        required: true
      },
      bio: {
        type: String,
        trim: true
      },
      profilePicture: {
        type: String 
      },
      status: {
        type: String,
        enum: ['online', 'offline', 'away'],
        default: 'offline'
      },
      lastLogin: {
        type: Date
      }
},{timestamps: true})

export const UserProfile = mongoose.model("UserProfile", userProfileSchema) 