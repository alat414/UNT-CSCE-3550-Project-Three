/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of the server with key
*           rotation; keyExpiry.js
************************************************* */
// Authenticate User
require('dotenv').config()

const express = require('express');

const jwt = require('jsonwebtoken')
const keyStorage = require('./keyStorage');
const { authenticateToken, getUserPosts } = require('./app.js')
const { userDB, authorization_logsDB } = require('./database');

const app = express();
const port = process.env.PORT || 8080;

const { db } = require('./database');

// Valid Users declared.
const VALID_USERS = ['Nanna', 'nanna', 'Raggi', 'raggi'];

const { body, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 10,
    message: { error: 'Too many login attempts, please try again later'},
    standardHeaders: true,
    legacyHeaders: false,
    skipSuccessfulRequests: true, 
});

const validatePasswordStrength = (password) => {
    const errors = [];

    if (password.length < 8)
    {
        errors.push('Password must be at least 8 characters long');
    }

    if (!/[A-Z]/.test(password))
    {
        errors.push('Password must contain at least one uppercase letter');
    }
    if (!/[a-z]/.test(password))
    {
        errors.push('Password must contain at least one lowercase letter');
    }
    if (!/[0-9]/.test(password))
    {
        errors.push('Password must contain at least one digit');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password))
    {
        errors.push('Password must contain at least one special character');
    }

    return errors;
}

app.use('/api/', limiter);

app.use(express.json())

let serverStarted = false;

async function startServer() 
{
    while (!keyStorage.initialized)
    {
        console.log('Waiting for keyStorage to initialize...');
        await new Promise(resolve => setTimeout(resolve, 100));
    }

    if (!serverStarted)
    {
        app.listen(port, () => 
        {
            console.log
            (`
                =====================================================
                JWKS Server with Key Rotation
                =====================================================
                KeyExpiry server running at http://localhost:${port}
                Database: jwks-server.test.db
                Active Key ID: ${keyStorage.getCurrentKeyID()}

                Available endpoints:
                -----------------------------------------------------
                - GET /.well-known/jwks.json    - Public JWKS endpoint
                - GET /health                   - Server health check
                - GET /key-status               - Detailed key information
                - GET /posts                    - Protected post information(authentication req)
                - GET /debug-keys               - Debugging key information (dev only)

                - POST /login                   - Authenticate and get tokens
                - POST /token                   - Refresh access token
                - POST /rotate-keys             - Rotate keys
                -----------------------------------------------------
            `);
        });

        serverStarted = true;
    }
}
/* *************************************************
* This function calls the JWKS endpoint. 
* Only includes active keys, not expired ones. 
* 
* @param: userdata
* @return:  all active public keys 
* @exception : none
* @note : na
* ************************************************* */

app.get('/.well-known/jwks.json', async (req, res) => 
{
    try 
    {
        const activeKeys = await keyStorage.getActiveKeys();
        res.json({ keys: activeKeys});
    } 
    catch (error) 
    {
        console.error('JWKS server endpoint error:', error)
        res.status(500).json({ error: 'Internal server error '});
    }
});

/* *************************************************
* This function request the refresh token. 
*
* @param : request
* @param : response
* @return : refresh token
* @exception : none
* @note : na
* ************************************************* */
app.post('/token', async (req, res) =>
{
    const refreshToken = req.body.token

    if (!refreshToken) 
    {
        console.log('Token refresh failed: No refresh token provided');
        return res.status(401).json({ error: 'Refresh token required '});
    }

    try 
    {
        const user = await new Promise((resolve, reject) => {
            jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, decoded) => {
                if (err)
                {
                    reject(err)
                }
                else 
                {
                    resolve(decoded);
                }
            });
        });
        const currentKey = await keyStorage.getCurrentKey();
        const currentKeyID = keyStorage.getCurrentKeyID();

        if(!currentKey || !currentKeyID)
        {
            console.error('Token refresh failed: No active key available');
            return res.status(500).json
            ({ 
                error: 'No active key available'
            });   
        }

        const keyData = await keyStorage.getKeyData(currentKeyID);
        if(!keyData || !keyData.isActive || new Date() > new Date(keyData.expiresIn))
        {
            console.error('Token refresh failed: Active key is expired');
            return res.status(500).json
            ({ 
                error: 'Active key expired'
            });   
        }

        const accessToken = jwt.sign
        (
            {
                name: user.name
            },
            currentKey,
            {
                expiresIn: '30s',
                header:
                {
                    kid: currentKeyID,
                    alg: 'HS256'

                }
            }
        );
        console.log(`Token refresh successful for user: ${user.name} using key ${currentKeyID}`);
        res.json({ accessToken: accessToken});
    }
    catch (err) 
    {
        console.log('Token refresh failed', err.message);
        res.status(403).json({ error: 'Invalid refresh token' });
    } 
});

/* *************************************************
* This function authenticates the user and issues
* tokens. First, validates the user through both
* username and password validation, second, ensures
* the key is valid, and then, access token is generated-
* both access and refresh tokens. Login endpoint also 
* keeps track of all login attempts and/or if account
* is locked. 


* @param req : request
* @param res : response
* @return : access or refresh token
* @exception : none
* @note : na
* ************************************************* */
app.post('/login', 
    limiter,  
    // validation middleware
    body('username').isString().notEmpty().withMessage('Username is required'),
    body('password').isString().notEmpty().withMessage('Password is required')
    .custom((value) => {
        const errors = validatePasswordStrength(value);
        if (errors.length > 0)
        {
            throw new Error(errors.join(', '));
        }
        return true;
    }),
    
    async (req, res) => 
{
    const { username, password } = req.body;
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.headers['user-agent'];

    const errors = validationResult(req);

    if(!errors.isEmpty())
    {
        return res.status(400).json
        ({
            errors: errors.array()
        });
    }

    if (!username || !password)
    {
        return res.status(400).json({ error: 'Username and password is required '});
    }

    // Check if the user exists in the DB.
    userDB.findUserByUsername(username, async (err, user) => 
    {
        if (err || !user) 
        {
            await authorization_logsDB.logAttempt(username, ipAddress, userAgent, false, 'User not found');
            return res.status(401).json({ error: 'Invalid credentials'});
        }

        // Check if the account is locked.
        if (user.lockedUntil && new Date(user.lockedUntil) > new Date()) 
        {
            return res.status(401).json
            ({ 
                error: 'Account locked',
                message: `Too many failed attempts. Try again after ${new Date(user.lockedUntil).toLocaleTimeString()}`
            });
        }

        // Verify the password
        const hashPassword = require('./database').hashPassword;
    
        if (hashPassword(password) !== user.password_hash)
        {
            await userDB.recordFailedLogin(username);
            await authorization_logsDB.logAttempt(username, ipAddress, userAgent, false, 'Invalid password');

            const failedAttempts = (user.failedLoginAttempts || 0) + 1;
            if (failedAttempts >= 5)
            {
                await userDB.lockUserAccount(username, 15);
            }

            return res.status(401).json
            ({
                error: 'Invalid credentials'
            
            });
        }

        // Successful login - update last login and log success.
        await userDB.updateLastLogin(username);
        await authorization_logsDB.logAttempt(username, ipAddress, userAgent, true);

        console.log(`Authorized user: ${username}`);
        const tokenUser = { name: username };

        try 
        {
            const aesKey = await keyStorage.getCurrentKey();
            const activeKeyID = keyStorage.getCurrentKeyID();
            
            if(!aesKey || !activeKeyID)
            {
                console.error('Login failed: No active key available');
                return res.status(500).json({ error: 'Server configuration error - No key available' });
            }

            const keyData = await keyStorage.getKeyData(activeKeyID);
            if(!keyData || !keyData.isActive || new Date() > new Date(keyData.expiresIn))
            {
                console.error('Login failed: Active key is expired');
                return res.status(500).json({ error: 'Key rotation in progress - please try again' });
            }

            const accessToken = jwt.sign
            (
                tokenUser,
                aesKey,
                {
                    expiresIn: '30s',
                    algorithm: 'HS256',
                    header: 
                    {
                        kid: activeKeyID,
                        alg: 'HS256'
                    }
                }
            );

            const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
            if (!refreshTokenSecret)
            {
                console.error('REFRESH_TOKEN_SECRET not set');
                return res.status(500).json({ error: 'Server Configuration Error'});
            }

            const refreshToken = jwt.sign(user, refreshTokenSecret, {expiresIn: '7d'});

            res.json
            ({ 
                accessToken: accessToken, 
                refreshToken: refreshToken,
                keyID: activeKeyID,
                keyExpiresIn: keyData.expiresIn,
                tokenExpiresIn: '30 seconds',
                algorithm: 'HS256',
                userId: user.id,
                role: user.role
            });

        } 
        catch (error) 
        {
            console.error('Login error:', error);
            res.status(500).json({ error:' Server Configuration error'})
        };

    })
});

/****************************************************
* This endpoint creates a new user account with 
* username, email, and password.

* @param req : request with registration info
* @param res : response with user details or error
*              messages
* @return : created user info 
* @exception : none
* @note : na
 ************************************************** */
app.post('/register',
    // Rate limiter for registration (preventing malicious activity) 
    rateLimit({
        windowMs: 60 * 60 * 1000, // one hour
        max: 5, // 5 registration attempts per hr.
        message: { error: 'Too many registration attempts, try again later'} 
    }),  


    // validation middleware
    body('username')
        .isString()
        .notEmpty()
        .withMessage('Username is required')
        .isLength({ min: 3, max: 50})
        .withMessage('Username must be more than 3 characters')
        .matches(/^[a-zA-Z0-9_]+$/)
        .withMessage('Username cannot contain special characters'),

    body('email')
        .isEmail()
        .withMessage('Valid email address is required')
        .normalizeEmail(),

    body('password')
        .isString()
        .notEmpty()
        .withMessage('Password is required')
        .isLength({ min: 8})
        .withMessage('Password must be at least 8 characters long')
        .matches(/[A-Z]/)
        .withMessage('Password must contain at least one uppercase character')
        .matches(/[a-z]/)
        .withMessage('Password must contain at least one lowercase character')
        .matches(/[0-9]/)
        .withMessage('Password must contain at least one digit')
        .matches(/[!@#$%^&*(),.?":{}|<>]/)
        .withMessage('Password must contain at least one special character'),
    
    async (req, res) => 
    {
        const { username, email,  password } = req.body;
        const ipAddress = req.ip || req.connection.remoteAddress;

        const errors = validationResult(req);
        if(!errors.isEmpty())
        {
            return res.status(400).json
            ({
                error: 'Validation failed',
                details: errors.array()
            });
        }

        try 
        {
            const existingUser = await Promise((resolve, reject) => 
            {
                userDB.findUserByUsername(username, (err, user) => 
                {
                    if (err)
                    {
                        reject(err);
                    }
                    else
                    {
                        resolve(user);
                    }
                })
            });
            
            if(existingUser)
            {
                return res.status(400).json({ error: 'Username', message: 'Please choose another username' });
            }

            const existingEmail = await Promise((resolve, reject) => 
            {
                db.get(`SELECT id FROM users WHERE email = ?`, [email], (err, row) => 
                {
                    if (err)
                    {
                        reject(err);
                    }
                    else
                    {
                        resolve(row);
                    }
                })
            });
            
            if(existingEmail)
            {
                return res.status(400).json({ error: 'Email used', message: 'Please choose another email address' });
            }

            const { hashPassword } = require('./database');
            const passwordHash = hashPassword(password);
            const createdAt = new Date().toISOString();
            const defaultRole = 'user';

            const result = await new Promise((resolve, reject) => {
                db.run(`INSERT INTO users (username, email, password_hash, role, createdAt, isActive)
                    VALUES (?, ?, ?, ?, ?, ?)`,
                    [username, email, passwordHash, defaultRole, createdAt, 1],
                    function (err)
                    {
                        if(err)
                        {
                            reject(err);
                        }
                        else
                        {
                            resolve(this.lastID);
                        }
                    }
                );
            })
            if(!keyData || !keyData.isActive || new Date() > new Date(keyData.expiresIn))
            {
                console.error('Login failed: Active key is expired');
                return res.status(500).json({ error: 'Key rotation in progress - please try again' });
            }

            const accessToken = jwt.sign
            (
                tokenUser,
                aesKey,
                {
                    expiresIn: '30s',
                    algorithm: 'HS256',
                    header: 
                    {
                        kid: activeKeyID,
                        alg: 'HS256'
                    }
                }
            );

            const refreshTokenSecret = process.env.REFRESH_TOKEN_SECRET;
            if (!refreshTokenSecret)
            {
                console.error('REFRESH_TOKEN_SECRET not set');
                return res.status(500).json({ error: 'Server Configuration Error'});
            }

            const refreshToken = jwt.sign(user, refreshTokenSecret, {expiresIn: '7d'});

            res.json
            ({ 
                accessToken: accessToken, 
                refreshToken: refreshToken,
                keyID: activeKeyID,
                keyExpiresIn: keyData.expiresIn,
                tokenExpiresIn: '30 seconds',
                algorithm: 'HS256',
                userId: user.id,
                role: user.role
            });

    } 
    catch (error) 
    {
        console.error('Login error:', error);
        res.status(500).json({ error:' Server Configuration error'})
    };

});

/* *************************************************
* This function returns posts for the authenticated 
* user.

* @param req : request
* @param res : response
* @return : user posts
* @exception : none
* @note : na
* ************************************************* */
app.get('/posts', authenticateToken, (req, res) => 
{
    console.log(`GET /posts - User: ${req.user.name}`);
    const userPosts = getUserPosts(req.user.name);
    res.json(userPosts);    
});

/* *************************************************
* This function successfully rotates the keys 
* previously generated. 

* @param req : request
* @param res : response
* @return : key ID and corresponding message
* @exception : none
* @note : na
* ************************************************* */
app.post('/rotate-keys', async (req, res) =>
{
    try
    {
        console.log('Rotating keys:');
        const days = req.body.expiresInDays || 1;
        
        const newKeyID = await keyStorage.generateNewKey(days);
        console.log(`New AES keys generated: ${newKeyID}`);

        const cleanedCount = await keyStorage.removeExpiredKeys();
        console.log(`Cleaned up keys : ${cleanedCount}`);

        const activeKeyData = await keyStorage.getKeyData(keyStorage.getCurrentKeyID());

        res.json
        ({
            success: true,
            message: 'Keys rotated successfully',
            newKeyID: newKeyID,
            activeKeyID: keyStorage.getCurrentKeyID(),
            activeKeyExpires: activeKeyData ? activeKeyData.expiresIn : null,
            cleanedupKeys: cleanedCount
        });
    }
    catch(error)
    {
        console.error('Error rotating keys:', error);
        res.status(500).json
        ({
            error: "Failed to rotate keys",
            details: error.message
        });
    }
});

/* *************************************************
* This function gets all the information about the keys.
* via try-catch method.

* @param req : request
* @param res : response
* @return status : key information
* @exception : none
* @note : na
* ************************************************* */
app.get('/key-status', async (req, res) =>
{
    try
    {
        const allKeys = await keyStorage.getAllKeys();
        const now = new Date();
        const currentKeyID = keyStorage.getCurrentKeyID();

        const status = allKeys.map(key => 
        ({
            kid: key.kid,
            createdAt: key.createdAt,
            expiresIn: key.expiresIn,
            isActive: key.isActive === 1,
            isCurrent: key.kid === currentKeyID,
            expired: now > new Date(key.expiresIn),
            timeToExpiry: new Date(key.expiresIn) - now
        }));

        res.json(status);
    }
    catch (error)
    {
        console.error('Key status error:', error);
        res.status(500).json({error: 'Internal server error'});
    }

});

/* *************************************************
* This function returns the server status.

* @param req : request
* @param res : response
* @return various : server information
* @exception : none
* @note : na
* ************************************************* */
app.get('/health', async (req, res) =>
{
    try 
    {
        const activeKeyData = await keyStorage.getKeyData(keyStorage.getCurrentKeyID());
        const allKeys = await keyStorage.getAllKeys();

        res.json
        ({
            status: 'OK',
            timestamp: new Date(),
            activeKeyID: keyStorage.getCurrentKeyID(),
            keyCount: allKeys.length,
            activeKeyValid: activeKeyData ? new Date() <= new Date(activeKeyData.expiresIn) : false,
            uptime: process.uptime(),
            database: 'SQLite (jwks-server.db)',
            encryption: 'AES-256-GCM'
        });
        
    } 
    catch (error) 
    {
        console.error('Health check error:', error);
        res.status(500).json({ status: 'Error', error: error.message});
    }
});

/* *************************************************
* This function saves key details;
* intended for development use only. 
*
* @param req : request
* @param res : response
* @return : none
* @exception : none
* @note : na
* ************************************************* */
app.get('/debug-key-status', async (req, res) => 
{
    try 
    {
        const allKeys = await keyStorage.getAllKeys();
        
        const now = new Date();
        
        const keyInfo = allKeys.map(key => 
        ({
            kid: key.kid,
            isActive: key.isActive === 1,
            createdAt: key.createdAt,
            expiresIn: key.expiresIn,
            isExpired: new Date(key.expiresIn) <= now
        }));
        
        res.json({
            currentTime: now.toISOString(),
            totalKeys: allKeys.length,
            keys: keyInfo,
            activeKeyCount: keyInfo.filter(k => k.isActive && !k.isExpired).length
        });
    } 
    catch (error) 
    {
        console.error('Debug key status error:', error);
        res.status(500).json({ error: error.message });
    }
});

/* *************************************************
* This function initalizes the server

* @param  : none
* @return : none
* @exception : none
* @note : na
* ************************************************* */

startServer();
module.exports = { app, keyStorage };