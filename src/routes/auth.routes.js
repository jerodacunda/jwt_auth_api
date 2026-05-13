const { Router } = require('express')
const { authenticate, authorize } = require('../middlewares/auth.middleware')
const controller = require('../controllers/auth.controller')

const router = Router()


// PUBLIC ROUTES

router.post('/register', controller.register)
router.post('/login', controller.login)
router.post('/refresh', controller.refresh)
router.post('/logout', controller.logout)


// PROTECTED ROUTES

router.get('/me', authenticate, controller.me)
// protected with authentication
// a valid token passes execution (next) to controller.me

router.get('/admin', authenticate, authorize('admin'), (req, res) => {
  res.json({ message: `Welcome admin ${req.user.email}` })
})
// protected with authentication & role 'admin' authorization


module.exports = router