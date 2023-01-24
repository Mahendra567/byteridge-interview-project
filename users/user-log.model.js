const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const userLogSchema = new Schema({
    userId:{type:String,required:true},
    loginAt :{type : Date},
    logoutAt :{ type : Date,default:null },
    clientIp:{type:String},
   
})
module.exports = mongoose.model('UserLogHistory',userLogSchema)