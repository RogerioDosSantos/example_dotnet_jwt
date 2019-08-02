using Jose;
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace jwt
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine($"1- Creating Plaintext Token (unprotected): ");
            string unprotectedToken = CreateUnprotectedToken();
            Console.WriteLine(unprotectedToken);
            Console.WriteLine("");

            Console.WriteLine($"2- Creating Signed Token (HS-* family): ");
            string hsToken = CreateHSToken();
            Console.WriteLine(hsToken);

            Console.WriteLine($"3- Creating Signed Token (RS-* and PS-* family): ");
            string rsToken = CreateRSToken();
            Console.WriteLine(rsToken);
            Console.WriteLine($"3A- Reading Signed Token (RS-* and PS-* family): ");
            string rsPayload = ReadRSToken(rsToken);
            Console.WriteLine(rsPayload);

            //Console.WriteLine($"4- Creating Signed Token (ES-* family): ");
            //string esToken = CreateESToken();
            //Console.WriteLine(rsToken);

        }

        static string CreateUnprotectedToken()
        {
            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };

            string token = Jose.JWT.Encode(payload, null, JwsAlgorithm.none);
            return token;
        }

        static string CreateHSToken()
        {
            //HS256, HS384, HS512 signatures require byte[] array key of corresponding length
            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };
            var secretKey = new byte[] { 164, 60, 194, 0, 161, 189, 41, 38, 130, 89, 141, 164, 45, 170, 159, 209, 69, 137, 243, 216, 191, 131, 47, 250, 32, 107, 231, 117, 37, 158, 225, 234 };
            string token = Jose.JWT.Encode(payload, secretKey, JwsAlgorithm.HS256);
            return token;
        }

        static string CreateRSToken()
        {
           //RS256, RS384, RS512 and PS256, PS384, PS512 signatures require RSA(usually private) key of corresponding length.
           var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };
            string currentDirectory = Directory.GetCurrentDirectory();
            string privateCertificatePath = Path.Combine(currentDirectory, "jwt_rs_cert.pfx");
            const string privateCertificatePassword = "example";
            X509Certificate2 signingCertificate = new X509Certificate2(privateCertificatePath, privateCertificatePassword);
            RSA privateKey = signingCertificate.GetRSAPrivateKey();
            string token = Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.RS256);
            return token;
        }

        static string ReadRSToken(string token)
        {
            string currentDirectory = Directory.GetCurrentDirectory();
            string publicCertificatePath = Path.Combine(currentDirectory, "jwt_rs_cert_public.pem");
            X509Certificate2 signingCertificate = new X509Certificate2(publicCertificatePath);
            RSA publicKey = signingCertificate.GetRSAPublicKey();
            string payload = Jose.JWT.Decode(token, publicKey);
            return payload;
        }

        static string CreateESToken()
        {
            //TODO(Roger): Create an ES certificate
            //ES256, ES384, ES512 ECDSA signatures can accept either CngKey(see above) or ECDsa (usually private) elliptic curve key of corresponding length.
            var payload = new Dictionary<string, object>()
            {
                { "sub", "mr.x@contoso.com" },
                { "exp", 1300819380 }
            };
            string currentDirectory = Directory.GetCurrentDirectory();
            string privateCertificatePath = Path.Combine(currentDirectory, "jwt_es_cert.pfx");
            const string privateCertificatePassword = "example";
            X509Certificate2 signingCertificate = new X509Certificate2(privateCertificatePath, privateCertificatePassword);
            ECDsa privateKey = signingCertificate.GetECDsaPrivateKey();
            string token = Jose.JWT.Encode(payload, privateKey, JwsAlgorithm.ES256);
            return token;
        }

        static string CreateJWTWithToken()
        {


            return "";
        }
    }
}
