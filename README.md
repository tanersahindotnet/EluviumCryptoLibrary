# EluviumCryptoLibrary
Eluvium Security &amp; Crypto Library for .Net

Eluvium crypto library is an open source, portable, easy to use, readable and flexible security library for .Net.
Use Eluvium's security infrastructure in your apps

# Services

**AeAes256CbcHmacSha512:** File encryption service for your files. It uses 256 bit CBC encryption with Sha512 and password verification for your files.

File Encryption Example:


```
     private readonly AeAes256CbcHmacSha512 _aesEncryptionService = new AeAes256CbcHmacSha512();

     _aesEncryptionService.EncryptFile(file, directoryPath + "/" + fileName + ".enc", _yourPassword, true);

     _aesEncryptionService.OnEncryptionProgress += _aesEncryptionService_OnEncryptionProgress;
     
     private void _aesEncryptionService_OnEncryptionProgress(int percentageDone, string message)
     {
            if (percentageDone == 100)
            {
              CompletedTextBlock.Text = "Completed";
            }
     }
```

File Decryption Example:

```
   private readonly AeAes256CbcHmacSha512 _aesEncryptionService = new AeAes256CbcHmacSha512();
   
   var result = _aesEncryptionService.DecryptFile(file, directoryPath + "/" + fileName, yourPassword , true);
   
   _aesEncryptionService.OnDecryptionProgress += _aesEncryptionService_OnDecryptionProgress;
   
   private void _aesEncryptionService_OnDecryptionProgress(int percentageDone, string message)
   {
          if (percentageDone == 100)
            {
              CompletedTextBlock.Text = "Completed";
            }
   }
```


**AesStringEncryptionService:** Encrypt string data using AesStringEncryptionService. It uses 256 bit AES CBC encryption to protect data. There are two methods for perform
encrypt and decrypt string data

```
EncryptString(string plainText, string passPhrase) // Encrypt string value

DecryptString(string encrypted, string passPhrase) // Decrypt string value
```


**DigitalSignatureService:**  They are used to send information to recipients who can verify that the information was sent from a trusted sender, using a public key.

```
CreatePublicAndPrivateKeyPair() // Returns two RSAParameters that contains private and public keys and also only returns public key

Sign(string message, RSAParameters privateAndPublicKeys) // Sign your message using private and public keys

Verify(string message, byte[] signature, RSAParameters publicKeyOnly) // Verify your message using public key only
```

**HashingService:** It allows you to hash your string data securely. Whereas encryption is a two-way function, hashing is a one-way function.
While it’s technically possible to reverse-hash something, the computing power required makes it unfeasible. Hashing is one-way.

```
string MultipleHash(string value) // Using them combined
string Sha256(string input)
string Sha384(string input)
string Sha512(string input)
```

**PasswordAdvisorService:** Password advisor service checks the Pwned Passwords API to see if the password has been seen in any data breaches. It's using k-anonymity
algorithm to securely search. Also checks your password's security level.

```
async Task<(bool passwordCompromised, int breachCount)> CheckPasswordAsync(string password) // breachCount value returns how 
// many times that password seen in that database and passwordCompromised returns true if that password has been compromised

PasswordScoreEnum CheckStrength(string password) // Checks your password's security level. 
//Return tipe is Enum that calculates security score of password from 0 to 5
```

**PasswordGeneratorService:** Generate secure passwords using PasswordGeneratorService service.

```
 string GeneratePassword(int length, bool lowercase, bool uppercase, bool number, bool character, bool special)
```


# Contribute

Code contributions are welcome! Please commit any pull requests against the master branch.

Security audits and feedback are welcome. Please open an issue or email us privately if the report is sensitive in nature.

More Info: http://eluvium.info/
