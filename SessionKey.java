import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

/* Discussion of Key Quality:
Quality of a key depends on a number of factors: For instance, Length, Randomness. 
In terms of the key length, different encryption algorithms may require different key sizes - for symmetric algorithms based around the
Feistel Structure, lengths of 128 bits are common, but greater lengths will give even better security against brute force attacks. Asymmetric 
encryption algorithms often require even greater key lengths, between 768-2048 bits, to be secure. This comes at a tradeoff though, as 
a longer key will reduce the speed of the encryption algorithm. Of course, it would be easy for a program to check the length of a key.

Randomness is a harder trait to measure, but is just as important for making keys hard to guess. Sometimes keys are 'randomly' generated 
using a generator sequence which has a very long period. It might be possible to check the quality of such a generator by creating a 
program which measures this period (and if the program determines that the period is too short, then the keys might not be considered 
great quality). We might also assume that a good random binary number generator will mostly produce numbers with a reasonably equal number
of 1s and 0s (since there would be a 50% chance of getting one or the other for each bit selection). So, we could write a program which
reads a number of keys of a certain length, and then counts the number of 1s and 0s in each key. If the key has a fairly equal distribution, 
we can consider it more 'random'.
*/

public class SessionKey {

    // Creates a session key for symmetric AES encryption

    private SecretKey sk;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException
    {    
        // creates a random SessionKey of the specified length (in bits). 
        try
        {
            KeyGenerator generator = KeyGenerator.getInstance("AES");
            generator.init(keylength);
            sk = generator.generateKey();
        }
        catch(NoSuchAlgorithmException ex)
        {
            System.out.println("Invalid Algorithm.");
        }
        
    }
    
    public SessionKey(byte[] keybytes)
    {
        // creates a SessionKey from a byte array. The byte array contains an existing key that is represented as a sequence of bytes
        sk = new SecretKeySpec(keybytes, "AES");
    }
    

    public SecretKey getSecretKey()
    {
        // This will return the secret key from our SessionKey object
        return sk;
    }

    public byte[] getKeyBytes()
    {
        // SessionKey class also needs to be able to export a key as a sequence of bytes. For this, we use the getKeyBytes() method
        return sk.getEncoded();
    }

}

