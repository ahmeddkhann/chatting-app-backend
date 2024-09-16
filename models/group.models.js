import mongoose, {Schema} from "mongoose";

const groupSchema = new Schema ({

    name: {
        type: String,
        required: true,
        trim: true
      },
      description: {
        type: String,
        trim: true
      },
      members: [
        {
          type: Schema.Types.ObjectId,
          ref: 'User'
        }
      ],
      createdAt: {
        type: Date,
        default: Date.now
      }
      
},{timestamps: true})

export const Conversation = mongoose.model("Conversation", groupSchema)