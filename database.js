/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of a database using SQLite3
*           into the current JWKS server (database.js) 
************************************************* */
// database.js - Simplified working version
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'jwks-server.db');
console.log(`Connecting to SQLite database at: ${dbPath}`);

const db = new sqlite3.Database(dbPath);

/** The following is a helper function to 
 * hash passwords in proper format
 * 
 * @param {*} password 
 * @returns A SHA 256 cryptographic hash of the given
 *          parameter as a hexadecimal string.
 */
function hashPassword(password)
{
    return crypto.createHast('sha256').update(password).digest('hex');
}

// Create all tables
db.serialize(() => {
    
    // =====================================================
    // 1. KEYS TABLE - For AES encryption keys
    // =====================================================
    db.run(`DROP TABLE IF EXISTS keys`);

    db.run(`CREATE TABLE IF NOT EXISTS keys (
        kid TEXT PRIMARY KEY,           // Key ID (e.g., "aes-1747123456789-abc123")
        secretKey TEXT NOT NULL,        // AES-256 key stored as base64
        createdAt TEXT NOT NULL,        // ISO timestamp when key was created
        expiresIn TEXT NOT NULL,        // ISO timestamp when key expires
        isActive INTEGER NOT NULL DEFAULT 1  // 1 = active, 0 = inactive/expired
    )`, (err) => 
    {
        if (err) 
        {
            console.error('Error creating keys table:', err.message);
        } 
        else 
        {
            console.log('Keys table created successfully (AES-256 storage)');
        }
    });

    // =====================================================
    // 2. USERS TABLE - For user accounts and authentication
    // =====================================================
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,    // SHA-256 hashed password
        role TEXT DEFAULT 'user',       // 'user' or 'admin'
        isActive INTEGER DEFAULT 1,     // 1 = active, 0 = disabled
        createdAt TEXT NOT NULL,
        lastLogin TEXT,
        failedLoginAttempts INTEGER DEFAULT 0,
        lockedUntil TEXT,
        createdBy TEXT
    )`, (err) => 
    {
        if (err) 
        {
            console.error('Error creating users table:', err.message);
        } 
        else 
        {
            console.log('Users table created successfully');
            
            // Insert default users
            const defaultUsers = 
            [
                { username: 'Nanna', password: 'Nanna123!', email: 'nanna@ofmonstersandmen.com', role: 'admin' },
                { username: 'Raggi', password: 'Raggi123!', email: 'raggi@ofmonstersandmen.com', role: 'user' }
            ];
            
            defaultUsers.forEach(user => 
            {
                const passwordHash = hashPassword(user.password);
                const createdAt = new Date().toISOString();
                
                db.run(`INSERT OR IGNORE INTO users (username, email, password_hash, role, createdAt)
                        VALUES (?, ?, ?, ?, ?)`,
                    [user.username, user.email, passwordHash, user.role, createdAt],
                    (err) => 
                    {
                        if (err) 
                        {
                            console.error(`Error creating default user ${user.username}:`, err.message);
                        } 
                        else 
                        {
                            console.log(`Default user '${user.username}' created (role: ${user.role})`);
                        }
                    }
                );
            });
        }
    });

    // =====================================================
    // 3. AUTH LOGS TABLE - Track authentication attempts
    // =====================================================
    db.run(`CREATE TABLE IF NOT EXISTS auth_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ipAddress TEXT,
        userAgent TEXT,
        success INTEGER DEFAULT 0,      // 1 = success, 0 = failure
        failureReason TEXT,
        timestamp TEXT NOT NULL
    )`, (err) => 
    {
        if (err) 
        {
            console.error('Error creating auth_logs table:', err.message);
        } 
        else 
        {
            console.log('Auth logs table created successfully');
        }
    });

    // =====================================================
    // 4. TOKENS TABLE - Track issued tokens (optional)
    // =====================================================
    db.run(`CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tokenId TEXT UNIQUE NOT NULL,
        userId INTEGER NOT NULL,
        tokenType TEXT NOT NULL,        // 'access' or 'refresh'
        issuedAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        revoked INTEGER DEFAULT 0,
        revokedAt TEXT,
        FOREIGN KEY (userId) REFERENCES users(id)
    )`, (err) => 
    {
        if (err) 
        {
            console.error('Error creating tokens table:', err.message);
        } 
        else 
        {
            console.log('Tokens table created successfully');
        }
    });
});

const userDB = 
{
    // Find user by username
    findUserByUsername: (username, callback) => 
    {
        db.get(`SELECT * FROM users WHERE username = ? AND isActive = 1`, [username], callback);
    },

    // Find user by ID
    findUserByID: (id, callback) =>
    {
        db.get(`SELECT id, username, email, role, createdAt, lastLogin FROM users WHERE id = ? AND isActive = 1`, [id], callback);
    },

    // Find user by email
    findUserByEmail: (email, callback) => 
    {
        db.get(`SELECT * FROM users WHERE email = ? AND isActive = 1`, 
            [email],
            callback
        ); 
    },

    createUserByEmail: (username, email, password, role = 'user', callback) => 
    {
        const createdAt = new Date().toISOString();

        db.run(`INSERT INTO users (username, email, password_hash, role, createdAt)
                VALUES (?, ?, ?, ?, ?)`,
            [username, email, password_hash, role, createdAt],
            callback
        );
    },
    // Create a new user
    createUser: (username, password, role = 'user', callback) => 
    {
        const password_hash = hashPassword(password);
        const createdAt = new Date().toISOString();

        db.run(`INSERT INTO users (username, password_hash, role, createdAt)
                VALUES (?, ?, ?, ?)`,
            [username, password_hash, role, createdAt],
            callback
        );
    },

    // Update last login time
    UpdateLastLogin: (username, callback) => 
    {
        const lastLogin = new Date().toISOString();

        db.run(`UPDATE users SET lastLogin = ?, failedLoginAttempts = 0 WHERE username = ?`,
            [lastLogin, username],
            callback
        );
    },

    // Record failed login attempt              
    recordFailedLogin: (username, callback) => 
    {
        const lastLogin = new Date().toISOString();

        db.run(`UPDATE users SET failedLoginAttempts = failedLoginAttempts + 1 WHERE username = ?`,
            [username],
            callback
        );
    },

    // Lock user account after too many failed attempts              
    lockUserAccount: (username, callback) => 
    {
        const lockedUntil = new Date(Date.now() + durationMinutes * 60000).toISOString();

        db.run(`UPDATE users SET lockedUntil = ? WHERE username = ?`,
            [lockedUntil, username],
            callback
        );
    },

    // Obtain the user's failed attempt count.           
    getFailedAttempts: (username, callback) => 
    {
        db.get(`SELECT failedLoginAttempts FROM users WHERE username = ?`,
            [username],
            callback
        );
    },


}

// Helper functions for logins to database
const authorization_logsDB = 
{
    // Login autnetication attempt
    logAttempt: (username, ipAddress, userAgent, success, failureReason = null, callback) => 
    {
        const timestamp = new Date().toISOString();
        db.run(`INSERT INTO auth_logs (username, ipAddress, userAgent, success, failureReason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)`, 
                [username, ipAddress, userAgent, success ? 1 : 0, failureReason, timestamp], callback);
    },

    // Get recent failed attempts for a user. 
    getRecentFailedAttempts: (username, minutes = 15, callback) => 
    {
        const since = new Date(Date.now() - minutes * 60000).toISOString();

        db.all(`SELECT COUNT (*) as count FROM auth_logs WHERE username = ? AND success = 0 AND timestamp > ?`,
            [username, since],
            callback
        );
    }
}

// Helper functions for logins to database
const tokenDB = 
{
    // Store issued token
    storeToken: (tokenID, userID, tokenType, expiresInSeconds, callback) => 
    {
        const issuedAt = new Date().toISOString();
        const expiresAt = new Date(Date.now() + expiresInSeconds * 1000).toISOString();

        db.run(`INSERT INTO tokens (tokenID, userID, tokenType, issuedAt, expiresAt)
                VALUES (?, ?, ?, ?, ?, ?)`, 
                [tokenID, userID, tokenType, issuedAt, expiresAt], callback);
    },

    // Revoke a token
    revokeToken: (tokenID, callback) => 
    {
        const revokedAt = new Date().toISOString();

        db.run(`UPDATE tokens SET revoked = 1, revokedAt = ? WHERE tokenID = ?` 
                [revokedAt, tokenID], callback);
    },

    // Check if the token is valid
    isTokenValid: (tokenID, callback) => 
    {
        const now = new Date().toISOString();

        db.get(`SELECT 1 FROM tokens WHERE tokenID = ? AND revoked = 0 AND expiresAt > ?`
                [tokenID, now], 
                (err, row) => callback(err, !!row));
    }
};

// Handle graceful shutdown
process.on('SIGTERM', () => {
    console.log('Closing database...');
    db.close();
});

process.on('SIGINT', () => {
    console.log('Closing database...');
    db.close();
});

module.exports = {db, onTableReady: (cb) => cb() };