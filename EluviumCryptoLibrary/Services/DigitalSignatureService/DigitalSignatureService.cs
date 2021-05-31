using System;
using System.Security.Cryptography;
using System.Text;

namespace EluviumCryptoLibrary.Services.DigitalSignatureService
{
    class DigitalSignatureService : IDigitalSignatureService
    {
        // They are used to send information to recipients who can verify that the information was sent from a trusted sender, using a public key.
        public Tuple<RSAParameters, RSAParameters> CreatePublicAndPrivateKeyPair()
        {
            RSAParameters privateAndPublicKeys, publicKeyOnly;
            using (var rsaAlg = RSA.Create())
            {
                privateAndPublicKeys = rsaAlg.ExportParameters(includePrivateParameters: true);
                publicKeyOnly = rsaAlg.ExportParameters(includePrivateParameters: false);
            }
            return Tuple.Create(privateAndPublicKeys, publicKeyOnly);
        }

        public byte[] Sign(string message, RSAParameters privateAndPublicKeys)
        {
            var rsaAlg = RSA.Create(privateAndPublicKeys);
            return rsaAlg.SignData(Encoding.UTF8.GetBytes(message), HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }

        public bool Verify(string message, byte[] signature, RSAParameters publicKeyOnly)
        {
            var rsaAlg = RSA.Create(publicKeyOnly);
            return rsaAlg.VerifyData(Encoding.UTF8.GetBytes(message), signature, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);
        }
    }
}
