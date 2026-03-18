let userController = require('../controllers/users')
let jwt = require('jsonwebtoken')
let fs = require('fs')
let path = require('path')

const publicKey = fs.readFileSync(path.join(__dirname, '../publicKey.pem'))

module.exports = {
    CheckLogin: async function (req, res, next) {
        try {
            let token = req.headers.authorization;
            if (!token) {
                res.status(401).send({ message: "ban chua dang nhap" })
                return;
            }
            let result = jwt.verify(token, publicKey, { algorithms: ['RS256'] })
            let user = await userController.GetAnUserById(result.id);
            if (!user) {
                res.status(401).send({ message: "ban chua dang nhap" })
                return;
            }
            req.user = user;
            next()
        } catch (error) {
            res.status(401).send({ message: "ban chua dang nhap" })
        }
    }
}