/** **************************************************
 * Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite, AES key, 
*              and hashing integrated
*  Purpose: A separate  file for password
*           generating functions for the 
*           current JWKS server (crypto.js) 
* ****************************************************/

const crypto = require('crypto');
const { v4: uuid4} = require('uuid');

class PasswordGenerator
{
    static uuidOnly(removeHyphens = true)
    {
        const pwd = uuid4();
        return removeHyphens ? pwd.replace(/-/g, '') : pwd;
    }
    static enhanced()
    {
        const uuidPart = uuid4().replace(/-/g, '');
        const randomPart = crypto.randomBytes(8).toString('hex');
        return `${uuidPart}${randomPart}`;
    }
    static highEntropy()
    {
        const bytes = crypto.randomBytes(32);
        return bytes.toString('hex');
    }
    static readable()
    {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890';
        let password = '';
        for (let i = 0; i < 24; i++)
        {
            password += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        return password;
    }
}

module.exports = PasswordGenerator;