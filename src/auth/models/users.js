'use strict';

const bcrypt = require('bcrypt');
const jwt=require('jsonwebtoken');
require('dotenv').config();

const userSchema = (sequelize, DataTypes) => {
  const model = sequelize.define('newtable', {
    username: { type: DataTypes.STRING, allowNull: false, unique: true },
    password: { type: DataTypes.STRING, allowNull: false, },
    token: {
      type: DataTypes.VIRTUAL,
      get() {
        return jwt.sign({ username: this.username  }, process.env.SECRET);
      },
      set(tokenObj) {
        return jwt.sign(tokenObj, process.env.SECRET ||'mysecretkey');
     }
    }
  });

  model.beforeCreate(async (user) => {
      user.password = await bcrypt.hash(user.password, 10);
  });

  // Basic AUTH: Validating strings (username, password) 
  model.authenticateBasic = async function (username, password) {
    const user = await this.findOne({where :{ username:username }})
    const valid = await bcrypt.compare(password, user.password)
    if (valid) { return user; }
    throw new Error('Invalid User');
  }

  // Bearer AUTH: Validating a token
  model.authenticateWithToken = async function (token) {
    try {
      const parsedToken = jwt.verify(token, process.env.SECRET ||'mysecertkey');
      const user =await this.findOne({where :{ username: parsedToken.username }})
      console.log("$$$$$$$$",user);
      if (user) { return user; }
      throw new Error("User Not Found");
    } catch (e) {
      throw new Error(e.message)
    }
  }

  return model;
}

module.exports = userSchema;