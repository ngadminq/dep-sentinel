const express = require('express');
const _ = require('lodash');
const app = express();
app.use(express.json());

// 运营同学可以在后台自定义通知模板
app.post('/notify/preview', (req, res) => {
  const render = _.template(req.body.tpl);
  res.send(render({ user: req.body.user }));
});

app.listen(3000);
