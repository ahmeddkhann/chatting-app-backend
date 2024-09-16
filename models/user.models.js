import mongoose, { Schema } from "mongoose";
import { boolean } from "webidl-conversions";

const userSchema = new Schema(
  {
    name: {
      type: String,
      required: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
    },

    username: {
      type: String,
      required: true,
      unique: true,
      minlength: 6,
      maxlength: 14,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },

    phone: {
      type: String,
      required: true,
    },

    address: {
      type: String,
      required: true,
      city: {
        type: String,
        required: true,
      },
      postalCode: {
        type: String,
        required: true,
      },
      state: {
        type: String,
        required: true,
      },
    },

    isActive:{
        type: boolean
    },
    
    isVerified: {
        type: Boolean,
    }
  },
  { timestamps: true }
);

export const User = mongoose.model("User", userSchema);
