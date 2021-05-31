using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace EluviumCore.Services.EncryptionService
{
    public class AeAes256CbcHmacSha512 : AesBase
    {
        #region fields

        private const int KeyBitSize = 256;
        private const int KeyBytesLength = (KeyBitSize / 8);


        private const int IvBitSize = 128;
        private const int IvBytesLength = (IvBitSize / 8);

        private const int SaltBitSize = 128;
        private const int SaltBytesLength = (SaltBitSize / 8);

        private const int TagBitSize = 256;
        private const int TagBytesLength = (TagBitSize / 8);

        private const int IterationsForKeyDerivationFunction = 100000;

        private const CipherMode CipherMode = System.Security.Cryptography.CipherMode.CBC;
        private const PaddingMode PaddingMode = System.Security.Cryptography.PaddingMode.PKCS7;

        #endregion fields

        #region constructors

        public AeAes256CbcHmacSha512()
        {
        }

        public AeAes256CbcHmacSha512(byte[] key, byte[] iv)
            : base(key, iv) { }

        #endregion constructors

        #region public methods
        #region file encryption

        /// <summary>
        /// Encrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="sourceFilePath">The input source file path to encrypt.</param>
        /// <param name="encryptedFilePath">The output file path to save the encrypted file. Pass null or an empty string to not generate a new file, encrypting only the input source file and mantaining its path.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after encryption or not.</param>
        /// <param name="appendEncryptionDataToOutputFile">Flag to indicate if the encryption additional data required to decrypt will be appended to the output file. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, string password, bool deleteSourceFile = false, bool appendEncryptionDataToOutputFile = true)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = "PasswordRequired"
                };
            }

            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            return EncryptFile(sourceFilePath, encryptedFilePath, passwordBytes, deleteSourceFile, appendEncryptionDataToOutputFile);
        }

        /// <summary>
        /// Encrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="sourceFilePath">The input source file path to encrypt.</param>
        /// <param name="encryptedFilePath">The output file path to save the encrypted file. Pass null or an empty string to not generate a new file, encrypting only the input source file and mantaining its path.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after encryption or not.</param>
        /// <param name="appendEncryptionDataToOutputFile">Flag to indicate if the encryption additional data required to decrypt will be appended to the output file. Enabling this option will not turn the encrypted data unsecure, but you'll have to provide that required info manually when you will do the decryption process.</param>
        public AesEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false, bool appendEncryptionDataToOutputFile = true)
        {
            if (string.IsNullOrWhiteSpace(encryptedFilePath))
            {
                encryptedFilePath = sourceFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = "PasswordRequired"
                };
            }

            try
            {
                //byte[] salt = CommonMethods.GenerateRandomBytes(_saltBytesLength);
                byte[] salt = CommonMethods.GenerateSalt();
                byte[] derivedKey = CommonMethods.GetHashedBytesFromPbkdf2(passwordBytes, salt, (KeyBytesLength * 2), IterationsForKeyDerivationFunction);

                byte[] cryptKey = derivedKey.Take(KeyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(KeyBytesLength).Take(KeyBytesLength).ToArray();

                var aesEncryptionResult = EncryptWithFileStream(sourceFilePath, encryptedFilePath, cryptKey, null, CipherMode, PaddingMode, deleteSourceFile);

                if (aesEncryptionResult.Success)
                {
                    if (appendEncryptionDataToOutputFile)
                    {
                        RaiseOnEncryptionMessage("FileAdditionalDataWriting");
                        byte[] additionalData = new byte[IvBytesLength + SaltBytesLength];

                        Array.Copy(aesEncryptionResult.Iv, 0, additionalData, 0, IvBytesLength);
                        Array.Copy(salt, 0, additionalData, IvBytesLength, SaltBytesLength);

                        CommonMethods.AppendDataBytesToFile(encryptedFilePath, additionalData);
                    }

                    //var hmacSha512 = CommonMethods.ComputeHMACSHA512HashFromFile(encryptedFilePath, authKey);
                    var hmacSha512 = new HmacSha512().ComputeFileHmac(encryptedFilePath, authKey).HashBytes;
                    var tag = hmacSha512.Take(TagBytesLength).ToArray();

                    if (appendEncryptionDataToOutputFile)
                    {
                        CommonMethods.AppendDataBytesToFile(encryptedFilePath, tag);
                        RaiseOnEncryptionMessage("FileAdditionalDataWritten");
                    }

                    aesEncryptionResult.Salt = salt;
                    aesEncryptionResult.Tag = tag;
                    aesEncryptionResult.AuthenticationKey = authKey;
                }

                return aesEncryptionResult;
            }
            catch (Exception ex)
            {
                return new AesEncryptionResult
                {
                    Success = false,
                    Message = $"ExceptionError\n{ex}"
                };
            }
        }

        #endregion file encryption

        #region file decryption

        /// <summary>
        /// Decrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided password string.
        /// </summary>
        /// <param name="encryptedFilePath">The input source encrypted file path do decrypt.</param>
        /// <param name="decryptedFilePath">The output file path to save the decrypted file. Pass null or an empty string to not generate a new file, decrypting only the input source encrypted file and mantaining its path.</param>
        /// <param name="password">The password string where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after decryption or not.</param>
        /// <param name="hasEncryptionDataAppendedInInputFile">Flag to indicate if the encryption additional data required to decrypt is present in the input source encrypted file. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="iv">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, string password, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true,
            byte[] sentTag = null, byte[] salt = null, byte[] iv = null)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "PasswordRequired"
                };
            }

            var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

            return DecryptFile(encryptedFilePath, decryptedFilePath, passwordBytes, deleteSourceFile, hasEncryptionDataAppendedInInputFile, sentTag, salt, iv);
        }

        /// <summary>
        /// Decrypts a file using AES with a 256 bits key in CBC mode with HMACSHA512 authentication, deriving the key from a provided byte array of the password.
        /// </summary>
        /// <param name="encryptedFilePath">The input source encrypted file path do decrypt.</param>
        /// <param name="decryptedFilePath">The output file path to save the decrypted file. Pass null or an empty string to not generate a new file, decrypting only the input source encrypted file and mantaining its path.</param>
        /// <param name="passwordBytes">The byte array of the password where the encryption key will be derived from.</param>
        /// <param name="deleteSourceFile">Flag to indicated whether the input source file will be deleted after decryption or not.</param>
        /// <param name="hasEncryptionDataAppendedInInputFile">Flag to indicate if the encryption additional data required to decrypt is present in the input source encrypted file. If true, retrieves this info from it, otherwise use the manually provided data via parameters.</param>
        /// <param name="sentTag">The previously generated byte array of the authentication tag. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="salt">The previously generated byte array of the salt used with the password to derive the decryption key. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <param name="iv">The previously generated byte array of the Initialization Vector used to initialize the first block. Leave empty or pass null if hasEncryptionDataAppendedInInputFile = true.</param>
        /// <returns>AesEncryptionResult</returns>
        public AesDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, byte[] passwordBytes, bool deleteSourceFile = false, bool hasEncryptionDataAppendedInInputFile = true,
            byte[] sentTag = null, byte[] salt = null, byte[] iv = null)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = $"EncryptedFileNotFound: \"{encryptedFilePath}\"."
                };
            }

            if (string.IsNullOrWhiteSpace(decryptedFilePath))
            {
                decryptedFilePath = encryptedFilePath;
            }

            if (passwordBytes == null || passwordBytes.Length <= 0)
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = "PasswordRequired"
                };
            }

            var encryptedFileSize = new FileInfo(encryptedFilePath).Length;

            if (hasEncryptionDataAppendedInInputFile)
            {
                if (encryptedFileSize < (TagBytesLength + SaltBytesLength + IvBytesLength))
                {
                    return new AesDecryptionResult
                    {
                        Success = false,
                        Message = "IncorrectInputLengthError"
                    };
                }
            }

            try
            {
                if (hasEncryptionDataAppendedInInputFile)
                {
                    byte[] additionalData = new byte[IvBytesLength + SaltBytesLength + TagBytesLength];
                    additionalData = CommonMethods.GetBytesFromFile(encryptedFilePath, additionalData.Length, (encryptedFileSize - additionalData.Length));

                    iv = new byte[IvBytesLength];
                    salt = new byte[SaltBytesLength];
                    sentTag = new byte[TagBytesLength];

                    Array.Copy(additionalData, 0, iv, 0, IvBytesLength);
                    Array.Copy(additionalData, IvBytesLength, salt, 0, SaltBytesLength);
                    Array.Copy(additionalData, (IvBytesLength + SaltBytesLength), sentTag, 0, TagBytesLength);
                }

                byte[] derivedKey = CommonMethods.GetHashedBytesFromPbkdf2(passwordBytes, salt, (KeyBytesLength * 2), IterationsForKeyDerivationFunction);
                byte[] cryptKey = derivedKey.Take(KeyBytesLength).ToArray();
                byte[] authKey = derivedKey.Skip(KeyBytesLength).Take(KeyBytesLength).ToArray();

                var hmacSha512 = new HmacSha512().ComputeFileHmac(encryptedFilePath, authKey, 0, (hasEncryptionDataAppendedInInputFile ? encryptedFileSize - TagBytesLength : encryptedFileSize)).HashBytes;
                var calcTag = hmacSha512.Take(TagBytesLength).ToArray();

                if (!CommonMethods.TagsMatch(calcTag, sentTag))
                {
                    return new AesDecryptionResult()
                    {
                        Success = false,
                        Message = "AuthenticationTagsMismatchError"
                    };
                }

                long endPosition = (hasEncryptionDataAppendedInInputFile ? (encryptedFileSize - TagBytesLength - SaltBytesLength - IvBytesLength) : encryptedFileSize);

                var aesDecryptionResult = DecryptWithFileStream(encryptedFilePath, decryptedFilePath, cryptKey, iv, CipherMode, PaddingMode, deleteSourceFile, 4, 0, endPosition);

                if (aesDecryptionResult.Success)
                {
                    aesDecryptionResult.Salt = salt;
                    aesDecryptionResult.Tag = sentTag;
                    aesDecryptionResult.AuthenticationKey = authKey;
                }

                return aesDecryptionResult;
            }
            catch (Exception ex)
            {
                return new AesDecryptionResult
                {
                    Success = false,
                    Message = $"ExceptionError\n{ex}"
                };
            }
        }

        #endregion file decryption

        #endregion public methods
    }
}