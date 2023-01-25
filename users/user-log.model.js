const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userLogSchema = new Schema({
    userId:{type:String,required:true},
    fullName : {type:String,required:true},
    isActive:{type:Boolean,default:false},
    logs:[{
    loginAt :{type : Date},
    logoutAt :{ type : Date,default:null },
    clientIp:{type:String},
    }]
   
})
module.exports = mongoose.model('UserHistory',userLogSchema)