const express = require('express');
const axios = require('axios');

const app = express();
const internal = axios.create({ baseURL: 'http://10.0.0.8:8080', headers: { 'X-Internal-Token': process.env.TOKEN } });

// 前端传入 path，服务端代为请求内部接口再把结果返回
app.get('/proxy', async (req, res) => {
  const { data } = await internal.get(req.query.path);
  res.json(data);
});

app.listen(3001);
