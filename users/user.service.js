const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;
const UserHistory = db.UserHistory;
module.exports = {
    authenticate,
    getAll,
    getById,
    create,
    update,
    delete: _delete,
    logout,
    getUserLogs
};

async function logout(id) {
    //need to expire token once log out .
    await UserHistory.update({userId:id,'logs.logoutAt':null},{ $set:{'logs.$.logoutAt': new Date(),'isActive':false }})
}

async function getUserLogs(id) {
    let user = await User.findOne({_id : id});
    if((user.role).toLowerCase() == 'auditor') {
        return await UserHistory.find();
    }
}

async function saveUserLog(data) {
    const ip = require('ip')
    let userHis = await UserHistory.findOne({userId : data.id});
    let obj = {
        loginAt : new Date(),
        clientIp:ip.address(),
    }
    if(!userHis) {
        let userLogObj={
            userId:data.id,
            isActive:true,
            fullName:data.firstName+" " + data.lastName,
            logs:[]
        };
        userLogObj.logs.push(obj);
        
        let userHistory = new UserHistory(userLogObj);
        await userHistory.save()
    } else {
      await UserHistory.updateOne({ userId : data.id },{ $push : {"logs": obj }})

        // throw new Error(`Please log out first!(visit-http://localhost:4000/users/logout/${data.id})`)
    }
}

async function authenticate({ username, password }) {
    const user = await User.findOne({ username });
    if (user && bcrypt.compareSync(password, user.hash)) {
        const { hash, ...userWithoutHash } = user.toObject();
        const token = jwt.sign({ sub: user.id }, config.secret);
        await saveUserLog(user); // Saving user login information during login
        return {
            ...userWithoutHash,
            token
        };
    }
}

async function getAll() {
    return await User.find().select('-hash');
}

async function getById(id) {
    return await User.findById(id).select('-hash');
}

async function create(userParam) {
    // validate
    if (await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    const user = new User(userParam);

    // hash password
    if (userParam.password) {
        user.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // save user
    await user.save();
}

async function update(id, userParam) {
    const user = await User.findById(id);

    // validate
    if (!user) throw 'User not found';
    if (user.username !== userParam.username && await User.findOne({ username: userParam.username })) {
        throw 'Username "' + userParam.username + '" is already taken';
    }

    // hash password if it was entered
    if (userParam.password) {
        userParam.hash = bcrypt.hashSync(userParam.password, 10);
    }

    // copy userParam properties to user
    Object.assign(user, userParam);

    await user.save();
}

async function _delete(id) {
    await User.findByIdAndRemove(id);
}