module.exports = {
    ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 3000,
    JWT_SECRET: process.env.JWT_SECRET || 'secret1',
    URL: process.env.URL || 'http://localhost:3000',
    MONGODB_URI: process.env.MONGODB_URI || 'mongodb://abc123!:abc123!@ds141611.mlab.com:41611/mcustomer_api'
}