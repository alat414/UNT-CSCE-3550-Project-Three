/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS Server with key id and token authentication.
*  Purpose: A demonstration of a properly
*           constructed and commented app.js
*           showing all middleware and utilities
*           for AES-256 JWT authentication. 
************************************************* */

require('dotenv').config()


const jwt = require('jsonwebtoken')
const keyStorage = require('./keyStorage');

/* *************************************************
* Post information used for the requests.

* @param l1 : a created username
* @param l2 : a created title
* @param m1 : a created username
* @param m2 : a created title
* @note : na
* ************************************************* */
const posts = 
[
    {
        username: "Nanna Bryndís Hilmarsdóttir",
        title: "lead singer"
    },
    {
        username: "Raggi Þórhallsson",
        title: "lead singer two"
    }

];


/* *************************************************
* This function accepts three parameter objects.
* passes the token and auth header by value into 
* the declared variables; the function validates the 
* key ID, and verifies the signature using AES 256.

* @param req : value passed by the request call
* @param res : value passed by the response
* @param next : value passed by the next function
* @return : na
* @note : na
* ************************************************* */
function authenticateToken(req, res, next) 
{
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) 
    {
        console.log('Authentication failed: No token provided');
        return res.status(401).json
        ({
            error: 'Authentication Required',
            message: 'No token provided in the Authorization Header'
        });
    }

    if (!token || !authHeader.startsWith('Bearer')) 
    {
        console.log('Authentication failed: Invalid Authorization header format');
        return res.status(401).json
        ({
            error: 'Authentication Required',
            message: 'Authorization header must use Bearer scheme'
        });
    }

    try 
    {
        const decodedHeader = jwt.decode(token, { complete: true });

        if (!decodedHeader) 
        {
            console.log('Authentication failed: Invalid token format');
            return res.status(401).json({ 
                error: 'Invalid token',
                message: 'Token cannot be decoded - malformed JWT' 
            });
        }

        if (!decodedHeader.header || !decodedHeader.header.kid) 
        {
            console.log('Authentication failed: No key ID in the token header');
            return res.status(401).json({ 
                error: 'Invalid token structure',
                message: 'Token missing key ID (kid) in header. Get a new token.' 
            });
        }
        
        if (!decodedHeader.header.alg !== 'HS256') 
        {
            console.log(`Authentication failed: Invalid algorithm ${decodedHeader.header.alg}`);
            return res.status(401).json({ 
                error: 'Invalid token structure',
                message: 'Only HS256 algorithm is supported' 
            });
        }

        const keyID = decodedHeader.header.kid;
        console.log(`Authenticating token with key ID: ${keyID}`);

        // Async key lookup
        keyStorage.getKey(keyID).then(keyBuffer => 
        {
            if (!keyBuffer) 
            {
                console.log(`Authentication failed: Key ID ${keyID} not found, expired, or inactive`);
                return res.status(401).json
                ({
                    error: 'Key invalid',
                    message: 'Token was signed with invalid, expired, or inactive key, retry.'
                });
            }
            
            jwt.verify(token, keyBuffer, { 
                algorithms: ['HS256']  ,
                maxAge: '30s'
            },  (err, user) => 
            {
                if (err) 
                {
                    if (err.name === 'TokenExpiredError') 
                    {
                        console.log(`Authentication failed: Token expired for key ${keyID}`);
                        return res.status(403).json
                        ({ 
                            error: 'Token Expired',
                            message: 'Your token has expired. Please use a refresh token to get a new one.'
                        });
                    }

                    if (err.name === 'JsonWebTokenError') 
                    {
                        console.log(`Authentication failed: Invalid signature for key ${keyID}`);
                        return res.status(403).json
                        ({ 
                            error: 'Invalid Token',
                            message: 'Token signature verification failed, possible tampered token.'
                        });
                    }

                    if (err.name === 'NotBeforeError') 
                    {
                        console.log(`Authentication failed: Token not yet active for key ${keyID}`);
                        return res.status(403).json
                        ({ 
                            error: 'Token Not Active',
                            message: 'Token not yet active. Please check your system time.'
                        });
                    }

                    console.log(`Authentication failed: ${err.message}`);
                    return res.status(403).json
                    ({ 
                        error: 'Token Verification Failed',
                        message: 'Unable to verify token. Please try logging in again.'
                    });
                }
                
                console.log(`Authentication successful for user: ${user.name} using key ${keyID}`);
                req.user = user;
                next();
            });
        }).catch(error => 
        {
            console.error('AES key lookup error:', error);
            return res.status(500).json({ 
                error: 'Internal server error',
                message: 'Error retrieving encryption key. Please try again later.'
            });
        });
        
    } 
    catch(error) 
    {
        console.error('Authentication middleware error:', error);
        return res.status(500).json
        ({ 
            error: 'Internal Server Error',
            message: 'Error processing authentication. Please try again.'
        });
    }
}

/* *************************************************
* Helper function to verify user's permissions

* @param req : request
* @param res : response
* @param next : next function
* @return : error message
* @note : na
* ************************************************* */
function requireUser(req, res, next)
{
    if (!req.user)
    {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'User not authenticated'
        });
    }
    next();
}

/* *************************************************
* Middleware for role-based access control.

* @param allowedRoles : Array of allowed role names.
* @return : Express middleware function.
* @note : na
* ************************************************* */
function requireRole(allowedRoles)
{
    return (req, res, next) => 
    {
        if (!req.user)
        {
            return res.status(401).json({
                error: 'Unauthorized',
                message: 'User not authenticated'
            });
        }

        if (allowedRoles.includes(req.user.role))
        {
            next();
        }
        else
        {
            res.status(403).json({
                error: 'Forbidden',
                message: 'Insufficient permissions'
            });
        }
    }
}

/* *************************************************
* Helper function to get posts filtered by username.
*
* @param username : The given username to filter posts.
* @return : Array of all filtered posts belonging to the 
*           respective user. 
* @note : na
* ************************************************* */
function getUserPosts(allowedRoles)
{
    
    if (!username || typeof username !== 'string')
    {
        console.log('getUserPosts called with invalid username:', username);
        return [];
    }

    const filteredPosts = posts.filter(post => 
        post.username.toLowerCase() === username.toLowerCase()
    );

    console.log(`getUserPosts: Found ${filteredPosts.length} posts for user ${username}`);
    return filteredPosts;
}

/* *************************************************
* Helper function to get all posts. 
*
* @param : na
* @return : array of posts
* @note : na
* ************************************************* */
function getAllPosts() 
{ 
    
    return [...posts];
    
}

/* *************************************************
* Helper function to add a new post (for expansion).
*
* @param username : The given username for the post author.
* @param title : The post title
* @return : The created post object
* @note : na
* ************************************************* */
function addPost(username, title)
{
    
    if (!username || !title)
    {
        throw new Error('Username and title are required');
    }

    const newPost = {
        username: username,
        title: title,
        id: posts.length + 1,
        createdAt: new Date().toISOString()
    };

    posts.push(newPost)
    return newPost;
}
/* *************************************************
* Export middleware and utilities

* @note : na
* ************************************************* */
module.exports = 
{ 
    authenticateToken,
    getUserPosts,
    getAllPosts,
    addPost,
    requireUser,
    requireRole,
    posts
};

