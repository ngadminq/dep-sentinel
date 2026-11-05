// 升级前/后各打一次：模拟攻击者提交的查询条件（CVE-2019-10744 原型链污染）。
// 不做破坏，只往 Object.prototype 写一个标记属性；别的空对象也能读到它就算打通。
const _ = require('lodash');

const evil = JSON.parse('{"constructor":{"prototype":{"polluted":"yes"}}}');
const DEFAULTS = { page: 1, size: 20 };
_.defaultsDeep({}, evil, DEFAULTS);   // 和 server.js 里一样的调用

const leaked = ({}).polluted;         // 一个全新的空对象
delete Object.prototype.polluted;
console.log(leaked === 'yes' ? 'EXPLOITED' : 'BLOCKED');
