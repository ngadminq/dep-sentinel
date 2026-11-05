// 项目自带冒烟测试：升级后正常的深合并还要照常工作。
const _ = require('lodash');
const out = _.defaultsDeep({}, { size: 50 }, { page: 1, size: 20 });
const ok = out.page === 1 && out.size === 50;
console.log(ok ? 'ok' : 'FAIL');
process.exit(ok ? 0 : 1);
