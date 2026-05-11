require('dotenv').config()

const express = require('express')
const authRoutes = require('./routes/auth.routes')
const app = express()

app.use(express.json())
app.use('/api/auth', authRoutes)

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`)
})