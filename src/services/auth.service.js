const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const { query } = require('../db')

// Hashing Rounds
const SALT_ROUNDS = 12

// --USERS--:

async function findUserByEmail(email) {
    const result = await query(
        `SELECT * FROM users WHERE email = $1`,
        [email]
    )
    return result.rows[0] // Returns first result or undefined
}

async function createUser(email, password) {
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS)

    const result = await query(
        `INSERT INTO users (email, password)
        VALUES ($1, $2)
        RETURNING id, email, role, created_at`,
        [email, hashedPassword]
    )
    return result.rows[0] //Never include password in RETURNING
}

async function verifyPassword(plainPassword, hashedPassword){
    return bcrypt.compare(plainPassword, hashedPassword)
}


// --TOKENS--:

function generateAccessToken(user) {
    const payload = { // user identification
        sub: user.id,
        email: user.email,
        role: user.role,
    }
    return jwt.sign(
        payload, 
        process.env.JWT_ACCESS_SECRET, 
        {expiresIn: process.env.JWT_ACCESS_EXPIRES}
    )
}

function generateRefreshToken(user) {
    const payload = {sub: user.id}
    return jwt.sign(
        payload, 
        process.env.JWT_REFRESH_SECRET, // access secret != refresh secret
        {expiresIn: process.env.JWT_REFRESH_EXPIRES, }
    )
}

async function saveRefreshToken(userId, token){
    const expiresAt = new Date()
    expiresAt.setDate(expiresAt.getDate() + 7) // session expire date set at 7 days

    await query(
        `INSERT INTO refresh_tokens (user_id, token, expires_at)
        VALUES ($1, $2, $3)`,
        [userId, token, expiresAt]
    )
}

async function findRefreshToken(token){
    const result = await query(
        'SELECT * FROM refresh_tokens WHERE token = $1',
        [token]
    )
    return result.rows[0]
}

async function deleteRefreshToken(token) {
    // logout -> deleting token from DB
    await query(
        'DELETE FROM refresh_tokens WHERE token = $1',
        [token]
    )
}

function verifyRefreshToken(token) {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET)

    // jwt.verify throws exception if invalid/expired token
    // to be handled with try/catch by caller
    // returns decoded payload if valid
}

module.exports = {
  findUserByEmail,
  createUser,
  verifyPassword,
  generateAccessToken,
  generateRefreshToken,
  saveRefreshToken,
  findRefreshToken,
  deleteRefreshToken,
  verifyRefreshToken,
}