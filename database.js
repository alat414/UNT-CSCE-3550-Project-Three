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
});

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