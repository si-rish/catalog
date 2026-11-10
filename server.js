// ==========================================
// CAMPUS EATS - SECURED REST API
// ==========================================

// Load environment variables
require('dotenv').config();

const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();

// ==========================================
// CONFIGURATION
// ==========================================

app.use(express.json());
app.use(express.static('public'));

const SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

// Stop the server if JWT_SECRET is missing
if (!SECRET) {
    console.error('ERROR: JWT_SECRET is missing from .env file');
    process.exit(1);
}

// ==========================================
// USERS
// ==========================================

// Demo users with bcrypt-hashed passwords

const users = [
    {
        id: 1,
        email: 'asha@campus.edu',
        role: 'customer',
        hash: bcrypt.hashSync('customer123', 10)
    },
    {
        id: 2,
        email: 'mealhub@campus.edu',
        role: 'restaurant',
        hash: bcrypt.hashSync('resto123', 10)
    },
    {
        id: 3,
        email: 'admin@campus.edu',
        role: 'admin',
        hash: bcrypt.hashSync('admin123', 10)
    }
];

// ==========================================
// INITIAL MENU
// ==========================================

let items = [
    { id: 1, name: 'Veg Thali', price: 90, veg: true },
    { id: 2, name: 'Paneer Roll', price: 70, veg: true },
    { id: 3, name: 'Chicken', price: 150, veg: false },
    { id: 4, name: 'Chicken Roll', price: 200, veg: false }
];

let nextId = 5;

// ==========================================
// PART 1: LOGIN API
// ==========================================

// POST /login
// Verify user credentials and generate JWT

app.post('/login', (req, res) => {

    const { email, password } = req.body || {};

    const user = users.find(u => u.email === email);

    if (
        !user ||
        typeof password !== 'string' ||
        !bcrypt.compareSync(password, user.hash)
    ) {
        return res.status(401).json({
            error: 'bad login'
        });
    }

    const token = jwt.sign(
        {
            sub: user.id,
            role: user.role
        },
        SECRET,
        {
            expiresIn: '1h'
        }
    );

    res.json({ token });
});

// ==========================================
// PART 2: AUTHENTICATION MIDDLEWARE
// ==========================================

// Verify JWT token before accessing protected routes

function auth(req, res, next) {

    const authorization = req.get('Authorization') || '';

    const parts = authorization.split(' ');

    if (
        parts.length !== 2 ||
        parts[0] !== 'Bearer' ||
        !parts[1]
    ) {
        return res.status(401).json({
            error: 'invalid or missing token'
        });
    }

    try {

        req.user = jwt.verify(parts[1], SECRET);

        next();

    } catch (error) {

        return res.status(401).json({
            error: 'invalid or missing token'
        });

    }
}

// ==========================================
// PART 3: AUTHORIZATION MIDDLEWARE
// ==========================================

// Check whether the logged-in user has permission

function requireRole(...allowed) {

    return (req, res, next) => {

        if (allowed.includes(req.user.role)) {
            return next();
        }

        return res.status(403).json({
            error: 'forbidden'
        });

    };

}

// ==========================================
// PART 4: GET ALL DISHES
// ==========================================

// Any authenticated user can view the menu

app.get('/items', auth, (req, res) => {

    if (req.query.veg === 'true') {

        return res.json(
            items.filter(item => item.veg === true)
        );

    }

    if (req.query.veg === 'false') {

        return res.json(
            items.filter(item => item.veg === false)
        );

    }

    res.json(items);

});

// ==========================================
// GET SINGLE DISH
// ==========================================

app.get('/items/:id', auth, (req, res) => {

    const item = items.find(
        i => i.id === Number(req.params.id)
    );

    if (!item) {

        return res.status(404).json({
            error: 'not found'
        });

    }

    res.json(item);

});

// ==========================================
// PART 5: ADD A DISH
// ==========================================

// Only restaurant and admin users can add dishes

app.post(
    '/items',
    auth,
    requireRole('restaurant', 'admin'),
    (req, res) => {

        const { name, price, veg } = req.body;

        if (typeof name !== 'string' || !name.trim()) {

            return res.status(422).json({
                error: 'name required'
            });

        }

        const parsedPrice = Number(price);

        if (
            price === undefined ||
            !Number.isFinite(parsedPrice) ||
            parsedPrice < 0
        ) {

            return res.status(422).json({
                error: 'valid price required'
            });

        }

        if (typeof veg !== 'boolean') {

            return res.status(422).json({
                error: 'valid food category required'
            });

        }

        const item = {
            id: nextId++,
            name: name.trim(),
            price: parsedPrice,
            veg: veg
        };

        items.push(item);

        res.status(201).json(item);

    }
);

// ==========================================
// PART 6: DELETE A DISH
// ==========================================

// Only restaurant and admin users can delete dishes

app.delete(
    '/items/:id',
    auth,
    requireRole('restaurant', 'admin'),
    (req, res) => {

        const id = Number(req.params.id);

        const index = items.findIndex(
            item => item.id === id
        );

        if (index === -1) {

            return res.status(404).json({
                error: 'not found'
            });

        }

        items.splice(index, 1);

        res.status(204).end();

    }
);

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, () => {

    console.log(
        `Secured CampusEats API running at http://localhost:${PORT}`
    );

});