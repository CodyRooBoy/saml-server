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
    res.redirect('/login');
});

app.get('/login', (req, res, next) => {
    const relayState = req.query.redirect ||  'http://localhost:3000/';
    req.session.relayState = relayState;
    passport.authenticate('saml', { passReqToCallback: true, successMessage: true, failureRedirect: '/' })(req, res, next);
});

app.post('/login/callback', async function(req, res) {
    const samlResponse = req.body.SAMLResponse;
    const decodedSamlResponse = Buffer.from(samlResponse, 'base64').toString('utf8');

    try {
        const response = await axios.post('http://localhost:3000/api/sso', decodedSamlResponse, {
            headers: {
                'Content-Type': 'application/xml',
            },
        });

        console.log('Response from Next.js server:', response.data);

        const relayState = req.session.relayState || 'http://localhost:3000/';
        res.redirect(relayState);
    } catch (error) {
        console.error('Error sending XML:', error.message);
        res.status(500).send('Error processing SAML response.');
    }
});

const httpsServer = https.createServer(credentials, app);

httpsServer.listen(process.env.PORT, () => {
    console.log(`HTTPS Server running on https://localhost:${process.env.PORT}`);
});