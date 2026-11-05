const axios = require('axios');

// 只调用内部固定地址的订单服务
const api = axios.create({ baseURL: 'https://orders.internal.example', timeout: 3000 });

async function getOrder(id) {
  const { data } = await api.get(`/orders/${Number(id)}`);
  return data;
}

module.exports = { getOrder };
