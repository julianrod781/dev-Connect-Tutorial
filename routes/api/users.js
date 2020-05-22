const express = require('express');
const router = express.Router();
// used to get gravatar
const gravatar = require('gravatar');
// used to encrypt password
const bcrypt = require('bcryptjs');
// Json web token for authentication
const jwt = require('jsonwebtoken');
const config = require('config');

//used to validate correct fields in req.body
const { check, validationResult } = require('express-validator');

// Bring in User model
const User = require('../../models/User');

//@route POST api/users
//@desc Register user
//@acess Public
router.post(
  '/',
  [
    check('name', 'Name us required').not().isEmpty(),
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 6 or more characters'
    ).isLength({ min: 6 }),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { name, email, password } = req.body;

    try {
      //See if user exists
      let user = await User.findOne({ email });

      if (user) {
        return res
          .status(400)
          .json({ errors: [{ msg: 'User already exist' }] });
      }
      // Get users gravatar
      const avatar = gravatar.url(email, {
        s: '200',
        r: 'pg',
        d: 'mm',
      });

      user = new User({
        name,
        email,
        avatar,
        password,
      });
      // Encrypt password
      const salt = await bcrypt.genSalt(10);

      user.password = await bcrypt.hash(password, salt);

      await user.save();
      // Return jsonwabtoken
      const payload = {
        user: {
          id: user.id,
        },
      };

      jwt.sign(
        payload,
        config.get('jwtSecret'),
        { expiresIn: 360000 },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (error) {
      console.log(error.message);
      res.status(500).send('Server Error');
    }
  }
);

module.exports = router;
