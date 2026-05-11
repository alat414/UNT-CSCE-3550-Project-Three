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

class passwordGenerator
{
    static uuidOnly(removeHyphens = true)
    {
        const pwd = uuid4();
        return removeHyphens ? pwd.replace(/-/g, '') : pwd;
    }
}