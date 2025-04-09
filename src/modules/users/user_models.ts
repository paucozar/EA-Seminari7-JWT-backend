import mongoose from "mongoose";
import { Auth } from "../auth/auth_model.js";

const userSchema = new mongoose.Schema(
    {
        name: {
            required: true,
            type: String
        },
        password: {
            type: String,
            required: true
        },
        age: {
            type: Number,
            default: '0'
        },
        email: {
            type: String,
            required: true,
            unique: true
        },
        googleId: { type: String },
        role: {
            type: String,
            default: 'user',
            enum: ['admin', 'user']
        }
    },
    {
        versionKey: false,
        timestamps: true,
    }
);

export interface IUser extends Auth{
    name : string;
    age : number;
    password: string;
    email: string;
    googleId: string;
    
}

const User = mongoose.model('User', userSchema);
export default User;
