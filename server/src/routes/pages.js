const express = require('express');
const { requireAuth, requireAdmin } = require('../middleware/auth');

const router = express.Router();

router.get('/', requireAuth, (req, res) => {
  res.render('landing', { user: req.session.user });
});

module.exports = router;
