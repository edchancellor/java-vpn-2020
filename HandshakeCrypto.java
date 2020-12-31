import java.security.cert.*;
import java.io.*;
import static javax.crypto.Cipher.*;
import javax.crypto.Cipher;
import java.security.Key;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.nio.file.*;
import java.nio.file.Paths;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;

import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import java.security.cert.CertificateException;

public class HandshakeCrypto
{
    /*
    Use the key pair from the previous step to encrypt and decrypt information with RSA.

    Your HandShakeCrypto class should be able to handle certificates and key files with RSA keys of any allowed size.
    */

    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        /*
        The encrypt method takes a plaintext as a byte array, and returns the corresponding cipher 
        text as a byte array. The key argument specifies the key – it can be a public key or private key. 
        */
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, NoSuchPaddingException, BadPaddingException
    {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, key);
        return c.doFinal(ciphertext);
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws FileNotFoundException, CertificateException
    {
        /*
        The getPublicKeyFromCertFile method extracts a public key from a certificate file (in PKCS#1 PEM format).
        */
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        FileInputStream stream = new FileInputStream(certfile);
        X509Certificate certificate = (X509Certificate)factory.generateCertificate(stream);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException
    {
        
        /*The getPrivateKeyFromKeyFile method extracts a private key from a key file (the file is in PKCS#8 DER format).*/ 
        /*
        Code inspired by: https://stackoverflow.com/questions/20119874/how-to-load-the-private-key-from-a-der-file-into-java-private-key-object
        */

        Path path_to_file = Paths.get(keyfile);
        byte[] private_key_array = Files.readAllBytes(path_to_file);

        PKCS8EncodedKeySpec private_key_spec = new PKCS8EncodedKeySpec(private_key_array);

        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey pk = factory.generatePrivate(private_key_spec);
        return pk;
   
    }

}