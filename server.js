// Required modules
const http = require('http');
const https = require('https');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const dns = require('dns');
const port = 3000;
const hostname = 'localhost';
const axios = require('axios');
const {post} = require("axios");



const db = mysql.createConnection({
    host: 'bl6b7f04rukmutftozcr-mysql.services.clever-cloud.com',
    user: 'urmyuojpdaauntpr',
    password: 'npC62BAkTzBHmxxQIYKP',
    database: 'bl6b7f04rukmutftozcr',
});

const JWT_SECRET = 'your_secret_key';

async function fetchPost(api, body) {
    return new Promise((resolve, reject) => {
        const url = new URL(api);

        const options = {
            hostname: url.hostname,
            path: url.pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(body)
            }
        };

        const req = https.request(options, (res) => {
            let response = '';

            res.on('data', (chunk) => {
                response += chunk;
            });

            res.on('end', () => {
                try {
                    resolve({
                        statusCode: res.statusCode,
                        data: response
                    });
                } catch (error) {
                    reject(`Error parsing response: ${error.message}`);
                }
            });
        });

        req.on('error', (error) => {
            reject(`Request error: ${error.message}`);
        });

        req.write(body);
        req.end();
    });
}


function fetchGet(url) {
    return new Promise((resolve, reject) => {
        https.get(url, (res) => {
            let data = '';

            res.on('data', (chunk) => {
                data += chunk;
            });

            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    data: data
                });
            });

        }).on('error', (err) => {
            reject({
                statusCode: null,
                error: err.message
            });
        });
    });
}





function queryAsync(sql, params) {
    return new Promise((resolve, reject) => {
        db.query(sql, params, (err, results) => {
            if (err) {
                reject(err);
            } else {
                resolve(results);
            }
        });
    });
}

function getSSLCertificateInfo(domain) {
    return new Promise((resolve, reject) => {
        const options = {
            method: 'GET',
            host: domain,
            port: 443,
            rejectUnauthorized: false,
        };

        const req = https.request(options, (res) => {
            const certificate = res.socket.getPeerCertificate();

            if (!certificate || Object.keys(certificate).length === 0) {
                reject('No certificate found');
                return;
            }

            resolve({
                subject: certificate.subject,
                issuer: certificate.issuer,
                valid_from: certificate.valid_from,
                valid_to: certificate.valid_to,
                is_valid: new Date(certificate.valid_to) > new Date(),
            });
        });

        req.on('error', (error) => {
            reject(error);
        });

        req.end();
    });
}

function resolveDomainToIP(domain) {
    return new Promise((resolve, reject) => {
        dns.resolve4(domain, (err, addresses) => {
            if (err) {
                console.error(`Помилка при перетворенні домену: ${err.message}`);
                reject(err);
                return;
            }
            resolve(addresses[0]);
        });
    });
}


http
    .createServer(async (req, res) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

        if (req.method === 'OPTIONS') {
            res.writeHead(204);
            res.end();
            return;
        }

        // POST request to /login
        if (req.method === 'POST' && req.url === '/login') {
            let body = '';

            req.on('data', (chunk) => {
                body += chunk;
            });

            req.on('end', async () => {
                try {
                    const parsedBody = JSON.parse(body);
                    const { login, password } = parsedBody;

                    if (!login || !password) {
                        res.writeHead(400, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Login and password are required' }));
                        return;
                    }

                    // Verify user credentials
                    const user = await queryAsync('SELECT * FROM register_User WHERE login = ? AND password = ?', [login, password]);

                    if (user.length === 0) {
                        res.writeHead(401, { 'Content-Type': 'application/json' });
                        res.end(JSON.stringify({ error: 'Invalid credentials' }));
                        return;
                    }

                    // Generate JWT token
                    const token = jwt.sign({ id: user[0].id, login: user[0].login }, JWT_SECRET, { expiresIn: '1h' });

                    // Send token to client
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ message: 'Login successful', token }));
                } catch (err) {
                    console.error('Error:', err.message);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Internal server error' }));
                }
            });

            req.on('error', (err) => {
                console.error('Error receiving data:', err.message);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Error receiving data' }));
            });
        }
        // else if (req.method === 'GET' && req.url === '/refresh-token') {
        //     // Example route to refresh token
        //     const authHeader = req.headers['authorization'];
        //     const token = authHeader && authHeader.split(' ')[1];
        //
        //     if (!token) {
        //         res.writeHead(401, { 'Content-Type': 'application/json' });
        //         res.end(JSON.stringify({ error: 'Token is required' }));
        //         return;
        //     }
        //
        //     jwt.verify(token, JWT_SECRET, (err, user) => {
        //         if (err) {
        //             res.writeHead(403, { 'Content-Type': 'application/json' });
        //             res.end(JSON.stringify({ error: 'Invalid or expired token' }));
        //             return;
        //         }
        //
        //         // Generate a new token
        //         const newToken = jwt.sign({ id: user.id, login: user.login }, JWT_SECRET, { expiresIn: '1h' });
        //
        //         res.writeHead(200, { 'Content-Type': 'application/json' });
        //         res.end(JSON.stringify({ message: 'Token refreshed', token: newToken }));
        //     });
        // }


        else if (req.method === 'GET' && req.url.startsWith('/certificate')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const domain = url.searchParams.get('domain');

            if (!domain) {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: 'Domain is required' }));
                return;
            }

            try {
                const certInfo = await getSSLCertificateInfo(domain);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(certInfo));
            } catch (err) {
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ error: `Failed to fetch SSL certificate: ${err.message}` }));
            }


        }

        else if (req.method === 'GET' && req.url.startsWith('/domain')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            const domain = url.searchParams.get('domain')

            try{
              let r =  await resolveDomainToIP(domain)
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify(r));
            }
            catch (error){
                console.log(error)
            }


        }

        else if (req.method === 'GET' && req.url.startsWith('/postman')) {
            const url = new URL(req.url, `http://${req.headers.host}`);
            let api = url.searchParams.get('api')
            let reqType = url.searchParams.get('reqType')
            let body = url.searchParams.get('body')

            body = (JSON.parse(body))
            api = (JSON.parse(api))

            console.log(body)
            try {
                let response;
                let statusCode;

                if (reqType === 'GET') {
                    try {
                        const result = await fetchGet(api);
                        response = JSON.parse(result.data);
                        statusCode = result.statusCode;
                    } catch (error) {
                        response = { error: error.message };
                        statusCode = error.statusCode || 500;
                    }
                } else if (reqType === 'POST') {
                    try {
                        const result = await fetchPost(api, JSON.stringify({ body }));
                        response = JSON.parse(result.data);
                        statusCode = result.statusCode;
                    } catch (error) {
                        response = { error: error.message };
                        statusCode = error.statusCode || 500;
                    }
                }

// Send response with status code and result
                res.writeHead(statusCode, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: statusCode, data: response }));

            } catch (error) {
                console.error(error);
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ status: 500, error: error.message }));
            }
        }




        else {
            // Handle unknown routes
            res.writeHead(404, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: 'Route not found' }));
        }
    })
    .listen(port, hostname, () => {
        console.log(`Server is working on http://${hostname}:${port}`);
    });
