/* *************************************************
*  Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite integrated
*  Purpose: Implementation of a database using SQLite3
*           into the current JWKS server (database.js) 
************************************************* */
// database.js - Simplified working version
const sqlite3 = require('sqlite3').verbose();
const path = require('path');

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

// Create table immediately
db.serialize(() => {
    //Remove any existing tables.
    db.run(`DROP TABLE IF EXISTS users`, (err) => {
        if (err) 
        {
            console.error('Error dropping table:', err.message);
        }
        else
        {
            console.log('Previous table removed');
        }
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )`, (err) => 
        {
            if (err) 
            {
                console.error('Error creating table:', err.message);
                process.exit(1);
            } 
            else 
            {
                console.log('AES keys table created successfully ');

                const defaultUsers = 
                [
                    {
                        username: 'Nanna',
                        password: 'LittleTalks123',
                        role: 'admin',
                    },
                    {
                        username: 'Raggi',
                        password: 'MountainSound098',
                        role: 'user'
                    }
                ];

                defaultUsers.forEach(user =>
                {
                    db.run(`INSERT OR IGNORE INTO users (username, password, role, createdAt)
                            VALUES (?, ?, ?, ?)`,
                        [user.username, hashPassword(user.password), user.role, new Date().toISOString()],
                        (err) => 
                        {
                            if (err)
                            {
                                console.error(`Error creating default user ${user.username}:`, err.message);
                            }
                            else
                            {
                                console.log(`Default user '${user.username}' created`);
                            }
                        });
                });
            }
        });
    });

    db.run(`CREATE TABLE IF NOT EXISTS authorization_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER, 
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => 
    {
        if (err)
        {
            console.error('Error creating authorization_logs tables', err.message);
        }
        else
        {
            console.log('Authorization logs table created successfully');
        } 
    });

    db.run(`CREATE TABLE IF NOT EXISTS tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tokenID TEXT UNIQUE NOT NULL,
        userID INTEGER NOT NULL,
        tokenType TEXT NOT NULL,
        issuedAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        revoked INTEGER DEFAULT 0,
        revokedAt TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )`, (err) => 
    {
        if (err)
        {
            console.error('Error creating tokens tables', err.message);
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
    findUserByUsername: (username, callback) => {
        db.get(`SELECT * FROM users WHERE username = ? AND isActive = 1`, [username], callback);
    },

    // Find user by ID
    findUserByID: (id, callback) => {
        db.get(`SELECT id, username, email, role, createdAt, lastLogin FROM users WHERE id = ? AND isActive = 1`, [id], callback);
    },

    // Create a new user
    createUser: (username, password, role = 'user', callback) => {
        const password_hash = hashPassword(password);
        const createdAt = new Date().toISOString();

        db.run(`INSERT INTO users (username, password_hash, role, createdAt)
                VALUES (?, ?, ?, ?)`,
            [username, password_hash, role, createdAt],
            callback
        );
    },

    // Update last login time
    UpdateLastLogin: (username, callback) => {
        const lastLogin = new Date().toISOString();

        db.run(`UPDATE users SET lastLogin = ?, failedLoginAttempts = 0 WHERE username = ?`,
            [lastLogin, username],
            callback
        );
    },

    // Record failed login attempt              
    recordFailedLogin: (username, callback) => {
        const lastLogin = new Date().toISOString();

        db.run(`UPDATE users SET failedLoginAttempts = failedLoginAttempts + 1 WHERE username = ?`,
            [username],
            callback
        );
    },

    // Lock user account after too many failed attempts              
    lockUserAccount: (username, callback) => {
        const lockedUntil = new Date(Date.now() + durationMinutes * 60000).toISOString();

        db.run(`UPDATE users SET lockedUntil = ? WHERE username = ?`,
            [lockedUntil, username],
            callback
        );
    },

}

// Helper functions for logins to database
const authorization_logsDB = 
{
    // Login autnetication attempt
    logAttempt: (username, ipAddress, userAgent, success, failure = null, callback) => {
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


}
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