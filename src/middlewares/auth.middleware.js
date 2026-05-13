const jwt = require('jsonwebtoken')


// Middleware is a function that receives (req, res, next)
// next function tells Express "Go to next Middleware/Handler"

function authenticate(req, res, next){

    // header verification -- 'authorization' contains access token
    const authHeader = req.headers['authorization']
    if (!authHeader) {
        return res.status(401).json({ error: 'token not given' })
    }

    // format: 'scheme token' ex: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    const [scheme, token] = authHeader.split(' ')
    if (scheme !== 'Bearer' || !token) {
        return res.status(401).json({ error: 'token: invalid format' })
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET)
        /* 
        jwt.verify validates:
        1. token is unaltered
        2. token is not expired
        3. token signed with JWT_ACCESS_SECRET 
        */

        req.user = payload
        // handlers extract decoded payload from req.user without revisiting token

        next()

    } catch(err) {
        return res.status(401).json({error: 'invalid or expired token'})
    }


    // Middleware authorizes by role of req.user (always after authenticate)

    function authorize(...roles){
        return (req, res, next) => {
            if (!roles.includes(req.user.role)){
                return res.status(403).json({error: 'action not allowed'})
            }
            // 403 Forbidden - authenticated but not allowed

            next()
        }        
    }


    module.exports = {authenticate, authorize}
}