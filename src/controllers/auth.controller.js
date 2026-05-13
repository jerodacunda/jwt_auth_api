const { z } = require('zod')
const authService = require('../services/auth.service')


// Validation schemas:

const registerSchema = z.object({
    email: z.string().min(1, 'email is required').email('invalid email'),
    password: z.string().min(8, 'password must be at least 8 characters')
})

const loginSchema = z.object({
    email: z.string().min(1, 'email is required').email('invalid email'),
    password: z.string().min(1, 'password is required')
})

const refreshSchema = z.object({
    refreshToken: z.string().min(1, 'refresh token is required')
})


// Handlers:

async function register(req, res) {
    try {
        const validation = registerSchema.safeParse(req.body)
        // safeParse returns object {success, data, error}

        if (!validation.success) {
            return res.status(400).json({
                error: 'invalid data',
                details: validation.error.errors.map(e => ({
                    field: e.path[0],
                    message: e.message,
                }))
            }) // 400: bad request
        }

        const {email, password} = validation.data

        // check existing email before insertion
        const existingUser = await authService.findUserByEmail(email)
        if (existingUser){
            return res.status(409).json({error: 'email is already registered'})
            // 409: resource already exists
        }

        const user = await authService.createUser(email, password)

        return res.status(201).json({
            message: 'user registered successfully',
            user
        })
    } catch (err) {
        console.error('failed to register', err)
        return res.status(500).json({error: 'internal server error'})
        // full error logged into server but not returned to user
    }
}

async function login(req, res){
    try {
        const validation = loginSchema.safeParse(req.body)
        if (!validation.success) {
            return res.status(400).json({
                error: 'invalid data',
                details: validation.error.errors.map(e => ({
                    field: e.path[0],
                    message: e.message,
                })),
            })
        }

        const {email, password} = validation.data
        const user = await authService.findUserByEmail(email)

        const dummyHash = '$2b$12$AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        // for protection from timing attack
        const passwordMatch = await authService.verifyPassword(
            password,
            user ? user.password : dummyHash
        )

        if (!user || !passwordMatch) {
            return res.status(401).json({ error: 'invalid credentials' })
        }

        const accessToken = authService.generateAccessToken(user)
        const refreshToken = authService.generateRefreshToken(user)

        await authService.saveRefreshToken(user.id, refreshToken)

        return res.status(200).json({
            accessToken,
            refreshToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
            },
        })
        // 200 ok.  improvement: refresh token on cookie not body
    } catch(err) {
        console.log('login error:', err)
        return res.status(500).json({error: 'internal server error'})
    }
}

async function refresh(req, res){}

async function logout(req, res){}

async function me(req, res){}


module.exports = {register, login, refresh, logout, me}