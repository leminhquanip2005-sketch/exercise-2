using System;
using System.Text;
using System.Security.Cryptography;

namespace RSADemo
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            // -------------------------------------------------------------
            // 1. GENERATE PUBLIC & PRIVATE KEY PAIRS FOR ALICE AND BOB
            // -------------------------------------------------------------
            using (RSA aliceRSA = RSA.Create(2048))
            using (RSA bobRSA = RSA.Create(2048))
            {
                Console.WriteLine("==================================================");
                Console.WriteLine("1. KEY PAIR GENERATION (RSA 2048-BIT)");
                Console.WriteLine("==================================================");
                Console.WriteLine("-> Successfully created key pair for Alice.");
                Console.WriteLine("-> Successfully created key pair for Bob.\n");

                // -------------------------------------------------------------
                // 2. TEXT ENCRYPTION & DECRYPTION (ALICE SENDS TO BOB)
                // -------------------------------------------------------------
                Console.WriteLine("==================================================");
                Console.WriteLine("2. TEXT ENCRYPTION AND DECRYPTION");
                Console.WriteLine("==================================================");
                string plainText = "Hello Bob, this is a confidential message from Alice.";
                Console.WriteLine($"[Original Text]: {plainText}");

                // Encrypt using Bob's Public Key
                byte[] encryptedData = EncryptText(plainText, bobRSA);
                Console.WriteLine($"[Encrypted Base64]: {Convert.ToBase64String(encryptedData).Substring(0, 45)}...");

                // Decrypt using Bob's Private Key
                string decryptedText = DecryptText(encryptedData, bobRSA);
                Console.WriteLine($"[Decrypted Text]: {decryptedText}\n");

                // -------------------------------------------------------------
                // 3. DIGITAL SIGNATURE & VERIFICATION (ALICE SIGNS)
                // -------------------------------------------------------------
                Console.WriteLine("==================================================");
                Console.WriteLine("3. DIGITAL SIGNATURE AND VERIFICATION");
                Console.WriteLine("==================================================");

                // Alice signs the data using her Private Key
                byte[] signature = SignData(plainText, aliceRSA);
                Console.WriteLine($"[Digital Signature Base64]: {Convert.ToBase64String(signature).Substring(0, 45)}...");

                // Verify signature using Alice's Public Key
                bool isSignatureValid = VerifyData(plainText, signature, aliceRSA);
                Console.WriteLine($"[Verification Result]: {isSignatureValid}");
                Console.WriteLine("==================================================");
            }

            Console.WriteLine("\nPress any key to exit...");
            Console.ReadKey();
        }

        // --- HELPER METHODS ---

        public static byte[] EncryptText(string plainText, RSA rsa)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(plainText);
            return rsa.Encrypt(dataBytes, RSAEncryptionPadding.OaepSHA256);
        }

        public static string DecryptText(byte[] encryptedData, RSA rsa)
        {
            byte[] decryptedBytes = rsa.Decrypt(encryptedData, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decryptedBytes);
        }

        public static byte[] SignData(string plainText, RSA rsa)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(plainText);
            return rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }

        public static bool VerifyData(string plainText, byte[] signature, RSA rsa)
        {
            byte[] dataBytes = Encoding.UTF8.GetBytes(plainText);
            return rsa.VerifyData(dataBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        }
    }
}
