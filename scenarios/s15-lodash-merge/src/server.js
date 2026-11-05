const express = require('express');
const _ = require('lodash');
const app = express();
app.use(express.json());

const DEFAULTS = { page: 1, size: 20, sort: 'created_at' };

// 用户可以提交自己的查询条件，和默认值深合并
app.post('/coupons/search', (req, res) => {
  const query = _.defaultsDeep({}, req.body, DEFAULTS);
  res.json({ query });
});

app.listen(3000);
