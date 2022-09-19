"use strict";
const { Model } = require("sequelize");
module.exports = (sequelize, DataTypes) => {
  class user extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
    }
  }
  user.init(
    {
      name: { type: DataTypes.STRING, allowNull: false },
      // email: { type: DataTypes.STRING, allowNull: false },
      // phone: { type: DataTypes.INTEGER },
      password: { type: DataTypes.STRING, allowNull: false },
      checkPoint: { type: DataTypes.INTEGER, defaultValue: 0 },
      highScore: { type: DataTypes.INTEGER, defaultValue: 0 },
    },
    {
      sequelize,
      modelName: "user",
    }
  );
  return user;
};
