const db = require("../models");
const config = require("../config/auth.config");
const multer = require("multer");
const { v4: uuidv4 } = require("uuid");
const User = db.user;
const Op = db.Sequelize.Op;

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");

const DIR = "./public/";

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, DIR);
    },
    filename: (req, file, cb) => {
        const fileName = file.originalname.toLowerCase().split(" ").join("-");
        cb(null, uuidv4() + "-" + fileName);
    },
});

exports.upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        // console.log(req);
        // console.log(file);
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error("Only .png, .jpg and .jpeg format allowed!"));
        }
    },
});

exports.signup = (req, res) => {
    const url = req.protocol + "://" + req.get("host");

    console.log(url + "/public/" + req.file.filename, "name");
    var profileImg = url + "/" + req.file.filename;
    // Save User to Database
    User.create({
        username: req.body.username,
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8),
        profileImg,
    })
        .then((user) => {
            res.send({ message: "User registered successfully!" });
            console.log(user);
        })
        .catch((err) => {
            res.status(500).send({ message: err.message });
        });
};

exports.signin = (req, res) => {
    User.findOne({
        where: {
            username: req.body.username,
        },
    })
        .then((user) => {
            if (!user) {
                return res.status(404).send({ message: "User Not found." });
            }

            var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);

            if (!passwordIsValid) {
                return res.status(401).send({
                    accessToken: null,
                    message: "Invalid Password!",
                });
            }

            var token = jwt.sign({ id: user.id }, config.secret, {
                expiresIn: 86400, // 24 hours
            });
            res.status(200).send({
                id: user.id,
                username: user.username,
                email: user.email,
                accessToken: token,
                profileImg: user.profileImg,
            });
        })
        .catch((err) => {
            res.status(500).send({ message: err.message });
        });
};
