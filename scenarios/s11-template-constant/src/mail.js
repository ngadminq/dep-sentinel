const _ = require('lodash');

// 模板写死在代码里，只有 name 字段来自数据库
const WELCOME = _.template('<p>你好，<%- name %>，欢迎加入！</p>');

function welcomeMail(user) {
  return WELCOME({ name: user.name });
}

module.exports = { welcomeMail };
