require('dotenv').config();
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
app.get('/health', (req, res) => res.json({ status: 'ok', service: process.env.SERVICE_NAME || 'unnamed' }));
app.get('/', (req, res) => res.json({ message: 'Replace this with your service code' }));
app.listen(PORT, () => console.log(`Running on port ${PORT}`));
