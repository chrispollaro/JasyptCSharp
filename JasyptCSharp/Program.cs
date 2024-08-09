namespace JasyptCSharp;

public class JasyptCompatibleEncryptionTest
{
    public static void Main(string[] args)
    {
        var plaintext = "This is the text that is being encrypted.";
        var password = "mySecretPassword";

        string encrypted = JasyptCompatibleEncryption.Encrypt(plaintext, password);
        Console.WriteLine("Encrypted: " + encrypted);


        string decrypted = JasyptCompatibleEncryption.Decrypt(encrypted, password);
        Console.WriteLine("Decrypted: " + decrypted);


        //.\encrypt input="The plaintext that is to be encrypted." password="mySecretPassword" verbose=true
        // algorithm=PBEWITHHMACSHA512ANDAES_256 ivGeneratorClassName="org.jasypt.iv.RandomIvGenerator"
        var test = @"EnrV+Y2UaVb5E20ZVpNXpX42c/WHoWyR/wSvQA0zt54BnuRpJNwr0W4Ue2P3B7RTZOknqpnD5Bay96W2PZoSURMVwPwQixxYN5kWQOpTx48=";
        string decryptedTest = JasyptCompatibleEncryption.Decrypt(test, password);
        Console.WriteLine("Test Decrypted: " + decryptedTest);
    }
}
