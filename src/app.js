var Crypto= require('crypto');  //add / import crypto module
var secret_key= 'fd85b494-aaaa';  // define secret key
var secret_iv = 'smslt';  // define secret IV
var encryptionMethod = 'AES-256-CBC';  // this is our encryption method 
var key = Crypto.createHash ('sha512').update (secret_key, 'utf-8').digest('hex').substring(0, 32); // create key 
var iv = Crypto.createHash('sha512').update (secret_iv, 'utf-8').digest('hex').substring(0, 16);  //same create iv using sha5


// now call encrpt function
var encryptedMessage = encrypt_string("hello", encryptionMethod, key, iv);
console.log(encryptedMessage); // output: L2d0ZjlDVmxoSDNWdmpVMkNGd0J Edz09 // store for decrpt

// add encrpt function
function encrypt_string(plain_text, encryptionMethod, secret, iv) {
    var encryptor = Crypto.createCipheriv(encryptionMethod, secret, iv); // encrpt using AES-256-CBC
    var aes_encrypted = encryptor.update(plain_text, 'utf8', 'base64') + encryptor.final('base64'); // convert to base64
    return Buffer.from (aes_encrypted).toString('base64');
    };


    // now call decrypt function
var decryptedMessage = decrypt_string("L2d0ZjlDVmxoSDNWdmpVMkNGd0JEdz09", encryptionMethod, key, iv);
console.log(decryptedMessage);

    // add decrypt function
    function decrypt_string(encryptedMessage, encryptionMethod, secret, iv) {
        const buff = Buffer.from(encryptedMessage, 'base64'); // get base64 string
        const decryptedString = buff.toString('utf-8'); // convert to string
        var decryptor = Crypto.createDecipheriv(encryptionMethod, secret, iv);
        return decryptor.update(decryptedString, 'base64', 'utf8') + decryptor.final('utf8');
      };
      
    
    