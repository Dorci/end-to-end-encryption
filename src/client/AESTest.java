package client;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class AESTest {
    public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        EncryptionAES encryptionAES = new EncryptionAES("mySecretPasssword");
        String message = "my message";
        String encryptedMessage = encryptionAES.encrypt(message);
        System.out.println(encryptedMessage);
        String originalMessage = encryptionAES.decrypt(encryptedMessage);
        System.out.println(originalMessage);
    }
}
