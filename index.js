import express from 'express';
import session from 'express-session';
import https from 'https';

import bodyParser from 'body-parser';

import passport from 'passport';
import { Strategy as SamlStrategy } from '@node-saml/passport-saml';

import fs from 'fs';

import axios from 'axios';

import dotenv from 'dotenv';
dotenv.config();

const privateKey = fs.readFileSync('ssl_certs/key.pem', 'utf8');
const certificate = fs.readFileSync('ssl_certs/cert.pem', 'utf8');
const idpCertificate = fs.readFileSync('saml_certs/cert.cer', 'utf8');

const PORT = process.env.PORT || 8000;

const credentials = { key: privateKey, cert: certificate };

const samlConfig = {
    entryPoint: process.env.SAML_ENTRY_POINT,
    issuer: process.env.SAML_ISSUER,
    callbackUrl: process.env.SAML_ACS,
    idpCert: idpCertificate,
    validateInResponseTo: 'never',
};

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(bodyParser.urlencoded({ extended: true }));

passport.use(new SamlStrategy(samlConfig, function(profile, done) {
    return done(null, profile);
}));

passport.serializeUser(function(user, done) {
    done(null, user);
});

passport.deserializeUser(function(user, done) {
    done(null, user);
});

app.get('/', (req, res) => {
    const serverStatus = {
        status: 'Running',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        port: PORT,
    };

    res.send(`
        <html>
            <head>
                <title>Server Status Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 20px; }
                    h1 { color: #333; }
                    p { font-size: 16px; }
                </style>
            </head>
            <body>
                <h1>Server Status Dashboard</h1>
                <p>Status: ${serverStatus.status}</p>
                <p>Timestamp: ${serverStatus.timestamp}</p>
                <p>Uptime: ${Math.floor(serverStatus.uptime)} seconds</p>
                <p>Host: ${process.env.HOST}</p>
                <p>Port: ${serverStatus.port}</p> <!-- Display the port -->
            </body>
        </html>
    `);
});

// Expected Query Strings: { redirect, returnUrl }
app.get('/login', (req, res, next) => {
    const redirect = req.query.redirect;
    const returnUrl = req.query.returnUrl;

    if (!redirect || !returnUrl) {
        return res.status(400).json({ error: 'Missing required query strings: redirect and returnUrl' });
    }

    req.session.redirect = redirect;
    req.session.returnUrl = returnUrl;

    passport.authenticate('saml', { passReqToCallback: true, successMessage: true, failureRedirect: redirect })(req, res, next);
});

app.post('/login/callback', async function(req, res) {
    const samlResponse = req.body.SAMLResponse;
    const decodedSamlResponse = Buffer.from(samlResponse, 'base64').toString('utf8');

    try {
        const response = await axios.post(req.session.returnUrl, decodedSamlResponse, {
            headers: {
                'Content-Type': 'application/xml',
            },
        });

        const redirectUrl = req.session.redirect;
        res.redirect(redirectUrl);
    } catch (error) {
        console.error('Error sending XML:', error.message);
        res.status(500).send('Error processing SAML response.');
    }
});

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(process.env.PORT, () => {
    console.log(`HTTPS Server running on ${process.env.HOST}:${PORT}`);
});