const config = require('config.js');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const db = require('_helpers/db');
const User = db.User;
const UserLogHistory = db.UserLogHistory;
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
    await UserLogHistory.updateOne({ userId : id ,logoutAt:null },{ $set:{'logoutAt' : new Date()}});
}

async function getUserLogs(id) {
    let user = await User.findOne({_id : id});
    if((user.role).toLowerCase() == 'auditor') {
        return await UserLogHistory.find();
    }
}

async function saveUserLog(data) {
    const ip = require('ip')
    let userHis = await UserLogHistory.findOne({"logoutAt":null},{userId : data.id});
    if(!userHis) {
        let obj = {
            userId:data.id,
            loginAt : new Date(),
            clientIp:ip.address(),
            isLogedIn:true
        }
        let userLogHistory = new UserLogHistory(obj);
        await userLogHistory.save()
    } else {
        throw new Error(`Please log out first!(visit-http://localhost:4000/users/logout/${data.id})`)
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