const express = require('express')
const {User} = require('../models/User')
const auth = require('../middleware/auth')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')



const router = express.Router()

const generateAuthToken =
async function(user) {
        // Generate an auth token for the user
        const token = jwt.sign({_id: user._id}, process.env.JWT_KEY)
        user.tokens = user.tokens.concat({token})
        await user.save()
        return token
    }

    const findByCredentials = async (email, password) => {
            // Search for a user by email and password.
            const user = await User.findOne({ email} )
            if (!user) {
                throw new Error({ error: 'Invalid login credentials' })
            }
            const isPasswordMatch = await bcrypt.compare(password, user.password)
            if (!isPasswordMatch) {
                throw new Error({ error: 'Invalid login credentials' })
            }
            return user
        }

router.post('/users', async (req, res) => {
    // Create a new user
    try {
        const pass = await bcrypt.hash(req.body.password, 8);
        req.body.password = pass;
        const user = new User(req.body)
        await user.save()
        const token = await generateAuthToken(user)
        console.log(pass)
        res.status(201).send({ user, token })
    } catch (error) {
        console.log(error)
        res.status(400).send(error)
    }
})

router.post('/users/login', async(req, res) => {
    //Login a registered user
    try {
        const { email, password } = req.body
        const user = await findByCredentials(email, password)
        if (!user) {
            return res.status(401).send({error: 'Login failed! Check authentication credentials'})
        }
        const token = await user.generateAuthToken()
        res.send({ user, token })
    } catch (error) {
        res.status(400).send(error)
    }

})

router.get('/users/me', auth, async(req, res) => {
    // View logged in user profile
    res.send(req.user)
})

module.exports = router
