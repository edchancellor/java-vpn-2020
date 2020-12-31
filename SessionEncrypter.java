import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import static javax.crypto.Cipher.*;
import javax.crypto.Cipher;

import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;

import javax.crypto.CipherOutputStream;
import java.io.OutputStream;

/*
SessionEncrypter will encrypt a stream of data.
It uses AES in CTR mode.
*/

public class SessionEncrypter {

    private IvParameterSpec IV;
    private Cipher cipher;
    private SessionKey sk;

    // With this constructor, the SessionEncrypter itself creates the parameters needed for AES in CTR mode, namely a key and counter (an IV)
    public SessionEncrypter(Integer keylength) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {    
        // SessionKey
        sk = new SessionKey(keylength);

        // cipher
        cipher = getInstance("AES/CTR/NoPadding");

        // IV (which acts as a counter) should be random
        SecureRandom Rand = new SecureRandom();
        byte [] array_for_IV = new byte[cipher.getBlockSize()];
        Rand.nextBytes(array_for_IV);
        IV = new IvParameterSpec(array_for_IV);
        
        // initiate cipher, which does the actual encryption.
        cipher.init(ENCRYPT_MODE,sk.getSecretKey(),IV);
    }
    
    // With this constructor, the SessionEncrypter is created from a given key and an IV
    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {
        sk = new SessionKey(keybytes);
        IV = new IvParameterSpec(ivbytes);
        cipher = getInstance("AES/CTR/NoPadding");
        cipher.init(ENCRYPT_MODE,sk.getSecretKey(),IV);
    }
    
    // Returns the IV as a byte array
    public byte[] getIVBytes()
    {
        return IV.getIV();
    }

    // Returns the key as a byte array
    public byte[] getKeyBytes()
    {
        return sk.getKeyBytes();
    }

    public CipherOutputStream openCipherOutputStream(OutputStream os)
    {
        // Creates a CipherOutputStream using an output stream and the cipher we have made.
        // The caller can use the returned CipherOutputStream to write plaintext data to it, 
        // and then the ciphertext data will go to the output stream "os". 
        CipherOutputStream stream = new CipherOutputStream(os, cipher);
        return stream;
    }

}

