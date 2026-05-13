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

async function login(req, res){}

async function refresh(req, res){}

async function logout(req, res){}

async function me(req, res){}


module.exports = {register, login, refresh, logout, me}