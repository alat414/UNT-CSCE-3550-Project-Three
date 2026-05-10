/** *******************************************************
 * Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite, AES key, and
*              hashing integrated
*  Purpose: A separate utility file for password
*           hashing for the current JWKS server (crypto.js) 
* **********************************************************/

const crypto = require('crypto');

/** The following is a helper function to 
 * hash passwords in proper format
 * 
 * @param {*} password 
 * @returns A SHA 256 cryptographic hash of the given
 *          parameter as a hexadecimal string.
 */
function hashPasswordSHA256(password)
{
    return crypto.createHast('sha256').update(password).digest('hex');
}