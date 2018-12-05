const errors = require('restify-errors');
const rjwt = require('restify-jwt-community');
const config = require('../config');
const Customer = require('../models/Customer');

module.exports = server => {
    //  Get All Customers
    server.get('/customers', async (req, res, next) => {
        try {
            // Customer.find({}, (err, docs) => {})
            const customers = await Customer.find({});
            res.send(customers);
            next();
        } catch (err) {
            return next(new errors.InvalidContentError(err));
        }
    });

    //  Get One Customer
    server.get('/customers/:id', async (req, res, next) => {
        try {
            // Customer.find({}, (err, docs) => {})
            const customer = await Customer.findById(req.params.id);
            res.send(customer);
            next();
        } catch (err) {
            return next(new errors.ResourceNotFoundError(`There is no customer with the Id of ${req.params.id}`));
        }
    });

    //  Add Customers
    server.post('/customers', rjwt({ secret: config.JWT_SECRET }), async (req, res, next) => {
        //  Check for JSON
        if (!req.is('application/json')) {
            return next(new errors.InvalidContentError('Expects "application/json"'));
        }
        const { name, email, balance } = req.body;
        const customer = new Customer({
            name, email, balance
        })

        try {
            const newCustomer = await customer.save();
            res.send(201);
            next();
        } catch (err) {
            return next(new errors.InternalError(err.message));
        }
    });

    //  Update customer details
    server.put('/customers/:id', rjwt({ secret: config.JWT_SECRET }), async (req, res, next) => {
        //  Check for JSON
        if (!req.is('application/json')) {
            return next(new errors.InvalidContentError('Expects "application/json"'));
        }
        try {
            const customer = await Customer.findOneAndUpdate({ _id: req.params.id }, req.body);
            res.send(200);
            next();
        } catch (err) {
            return next(new errors.ResourceNotFoundError(`There is no customer with the Id of ${req.params.id}`));
        }
    });

    //  Delete Customer
    server.del('/customers/:id', rjwt({ secret: config.JWT_SECRET }), async (req, res, next) => {
        try {
            const customer = await Customer.findOneAndRemove({ _id: req.params.id });
            res.send(204);
            next();
        } catch (err) {
            return next(new errors.ResourceNotFoundError(`There is no customer with the Id of ${req.params.id}`));
        }
    });
};