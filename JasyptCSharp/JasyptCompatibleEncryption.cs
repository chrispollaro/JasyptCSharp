using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace JasyptCSharp;

// Class for compatibility with Jasypt PBEWITHHMACSHA512ANDAES_256 encrypt using a random IV and AES-CBC
public class JasyptCompatibleEncryption
{
    private const int ITERATIONS = 1000;
    private const int KEY_SIZE = 256;
    private const int SALT_SIZE = 16;
    private const int IV_SIZE = 16;

    public static string Encrypt(string plaintext, string password)
    {
        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().NextBytes(salt);
        new SecureRandom().NextBytes(iv);

        byte[] key = GenerateKey(password, salt);

        BufferedBlockCipher cipher = SetupCipher(true, key, iv);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] encryptedBytes = ProcessBytes(cipher, plaintextBytes);

        byte[] result = new byte[salt.Length + iv.Length + encryptedBytes.Length];
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(iv, 0, result, salt.Length, iv.Length);
        Buffer.BlockCopy(encryptedBytes, 0, result, salt.Length + iv.Length, encryptedBytes.Length);

        return Convert.ToBase64String(result);
    }

    public static string Decrypt(string ciphertext, string password)
    {
        byte[] ciphertextBytes = Convert.FromBase64String(ciphertext);

        byte[] salt = new byte[SALT_SIZE];
        byte[] iv = new byte[IV_SIZE];
        Buffer.BlockCopy(ciphertextBytes, 0, salt, 0, SALT_SIZE);
        Buffer.BlockCopy(ciphertextBytes, SALT_SIZE, iv, 0, IV_SIZE);

        byte[] key = GenerateKey(password, salt);

        BufferedBlockCipher cipher = SetupCipher(false, key, iv);

        byte[] encryptedBytes = new byte[ciphertextBytes.Length - SALT_SIZE - IV_SIZE];
        Buffer.BlockCopy(ciphertextBytes, SALT_SIZE + IV_SIZE, encryptedBytes, 0, encryptedBytes.Length);

        byte[] decryptedBytes = ProcessBytes(cipher, encryptedBytes);

        return Encoding.UTF8.GetString(decryptedBytes);
    }


    private static byte[] GenerateKey(string password, byte[] salt)
    {
        var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha512Digest());
        pdb.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), salt, ITERATIONS);

        var parameters = (ParametersWithIV)pdb.GenerateDerivedParameters("AES", KEY_SIZE, IV_SIZE * 8);

        return ((KeyParameter)parameters.Parameters).GetKey();
    }

    private static BufferedBlockCipher SetupCipher(bool forEncryption, byte[] key, byte[] iv)
    {
        IBlockCipher engine = new AesEngine();
        BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(engine), new Pkcs7Padding());
        cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
        return cipher;
    }

    private static byte[] ProcessBytes(BufferedBlockCipher cipher, byte[] input)
    {
        byte[] output = new byte[cipher.GetOutputSize(input.Length)];
        int length = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        length += cipher.DoFinal(output, length);

        byte[] result = new byte[length];
        Array.Copy(output, 0, result, 0, length);
        return result;
    }
}
