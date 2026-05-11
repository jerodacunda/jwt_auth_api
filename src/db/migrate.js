require('dotenv').config()
const { query } = require('./index')

async function migrate() {
    await query(`
        CREATE TABLE IF NOT EXISTS users (
        id       SERIAL PRIMARY KEY,
        email    VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role     VARCHAR(50) NOT NULL DEFAULT 'user',
        created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `)

    await query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
        id         SERIAL PRIMARY KEY,
        user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token      TEXT NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
        )
    `)

    console.log('Migración completada')
    process.exit(0)

    migrate().catch(err => {
        console.error('Error en migración:', err)
        process.exit(1)
    })
}