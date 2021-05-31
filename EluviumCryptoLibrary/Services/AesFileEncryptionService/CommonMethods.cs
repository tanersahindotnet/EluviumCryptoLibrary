using System;
using System.IO;
using System.Security.Cryptography;

namespace EluviumCore.Services.EncryptionService
{
    public static class CommonMethods
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider())
            {
                rngCsp.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        public static byte[] Generate128BitKey()
        {
            return GenerateRandomBytes(128 / 8);
        }

        public static byte[] GenerateSalt(int saltLength = 0)
        {
            return (saltLength == 0 ? Generate128BitKey() : GenerateRandomBytes(saltLength));
        }

        public static byte[] GetHashedBytesFromPbkdf2(byte[] passwordBytes, byte[] saltBytes, int keyBytesLength, int iterations/*, HashAlgorithmName hashAlgorithmName*/)
        {
            byte[] pbkdf2HashedBytes;

            using (var pbkdf2 = new Rfc2898DeriveBytes(passwordBytes, saltBytes, iterations/*, hashAlgorithmName*/))
            {
                pbkdf2HashedBytes = pbkdf2.GetBytes(keyBytesLength);
            }

            return pbkdf2HashedBytes;
        }

        public static void ClearFileAttributes(string filePath)
        {
            if (!File.Exists(filePath))
                throw new FileNotFoundException($"FileNotFound {filePath}.", nameof(filePath));

            File.SetAttributes(filePath, FileAttributes.Normal);
        }

        public static void AppendDataBytesToFile(string filePath, byte[] dataBytes)
        {
            using (var fs = File.Open(filePath, FileMode.Append, FileAccess.Write, FileShare.None))
            {
                fs.Write(dataBytes, 0, dataBytes.Length);
            }
        }

        public static byte[] GetBytesFromFile(string filePath, int dataLength, long offset = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"FileNotFound {filePath}.", filePath);
            }

            if (dataLength < 1)
            {
                throw new ArgumentException($"InvalidDataLengthError ({dataLength}).", nameof(dataLength));
            }

            byte[] dataBytes = new byte[dataLength];

            using (FileStream fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fStream.Seek(offset, SeekOrigin.Begin);
                fStream.Read(dataBytes, 0, dataLength);
                fStream.Close();
            }

            return dataBytes;
        }

        public static bool TagsMatch(byte[] calcTag, byte[] sentTag)
        {
            if (calcTag.Length != sentTag.Length)
                throw new ArgumentException("IncorrectTagsLength");

            var result = true;
            var compare = 0;

            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }

            if (compare != 0)
                result = false;

            return result;
        }
    }
}