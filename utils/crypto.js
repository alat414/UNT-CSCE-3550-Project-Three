/** *******************************************************
 * Name: Gustavo Alatriste
*  Assignment: JWKS server with SQLite, AES key, and
*              hashing integrated
*  Purpose: A separate utility file for password
*           hashing for the current JWKS server (crypto.js) 
* **********************************************************/

const crypto = require('crypto');

/** *******************************************************
 * The following is a helper function to 
 * hash passwords in proper format
 * 
 * @param {*} password 
 * @returns A SHA 256 cryptographic hash of the given
 *          parameter as a hexadecimal string.
******************************************************* */
function hashPasswordSHA256(password)
{
    return crypto.createHast('sha256').update(password).digest('hex');
}

/** *******************************************************
 * The following function generates a password using 
 * UUID v4.
 * 
 * @param {boolean} remove hyphens - whether to remove the hyphens 
 * @returns string - generated password
 * @note na
 **********************************************************/
function generateSecurePassword(removeHyphens = true)
{
    const { v4: uuidv4 } = require('uuid');
    const password = uuidv4();

    return removeHyphens ? password.replace(/-/g, '') : password;
}

/** *******************************************************
 * The following function verifies a password aganist  
 * the hash.
 * 
 * @param {string} password - Plain text password to verify 
 * @param {string} hash - Stored SHA-256 hash
 * @returns {boolean} - True if the password matches the hash
 * @note na
 **********************************************************/
function verifyPasssword(password, hash)
{
    return hashPasswordSHA256(password) === hash;
}

/** *******************************************************
 * The following function generates a password with
 * enhanced complexity. 
 *  
 * @param na
 * @returns {object} - plain password and hash
 * @note na
 **********************************************************/
function generateEnhancedPassword()
{
    const { v4: uuidv4 } = require('uuid');
    const randomBytes = crypto.randomBytes(8).toString('hex');
    const plainPassword = `${uuidv4().replace(/-/g, '')}${randomBytes}`;
    const passwordHash = hashPasswordSHA256(plainPassword);

    return {
        plain: plainPassword,
        hash: passwordHash,
        length: plainPassword.length
    };
}

module.exports ={
    hashPasswordSHA256,
    generateSecurePassword,
    verifyPasssword,
    generateEnhancedPassword,
}