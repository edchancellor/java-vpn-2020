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

import javax.crypto.CipherInputStream;
import java.io.InputStream;


/* 
SessionDecrypter will decrypt a stream of data.
It uses AES in CTR mode.
*/

public class SessionDecrypter {

    private IvParameterSpec IV;
    private Cipher cipher;
    private SessionKey sk;

    // With this constructor, the SessionDecrypter itself creates the parameters needed for AES in CTR mode, namely a key and counter (an IV)
    public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException
    {    
        // sk
        sk = new SessionKey(keybytes);

        // cipher
        cipher = getInstance("AES/CTR/NoPadding");

        // IV
        IV = new IvParameterSpec(ivbytes);
        
        // initiate cipher
        cipher.init(DECRYPT_MODE,sk.getSecretKey(),IV);
    }
    
    public CipherInputStream openCipherInputStream(InputStream in)
    {
        //Given an input stream, will use the cipher to decipher it.
        CipherInputStream stream = new CipherInputStream(in, cipher);
        return stream;
    }

}
