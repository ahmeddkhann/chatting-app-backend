import mongoose, {Schema} from "mongoose";

const messageSchema = new Schema ({

    sender: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    reciever: {
        type: Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    content: {
        type: String,
        required: true
    },
    isRead: {
        type: Boolean,
    },
    sentAt: {
        type: Date,
        default: Date.now
    },
    messageType: {
        type: String,
        enum: ["text", "image", "video", "file", "voiceNote"],
        default: "text"
    }

},{timestamps: true})

export const Message = mongoose.model("Message", messageSchema)