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
        )`, (err) => {
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

                
            }
        });
    });

    db.run(`CREATE TABLE IF NOT EXISTS user`)
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