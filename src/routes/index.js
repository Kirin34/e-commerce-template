const router = require('express').Router();

router.use('/auth', require('./auth.routes'));
router.use('/addresses', require('./address.routes'));
router.use('/admin', require('./admin.routes'));

module.exports = router;