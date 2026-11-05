const express = require('express');
express().get('/ok', (_, r) => r.send('ok')).listen(8080);
