// cspHeaders.js

module.exports = function (req, res, next) {
    res.setHeader("Content-Security-Policy", "default-src 'self'; script-src 'self' https://trustedscripts.example.com;");
    next();
};