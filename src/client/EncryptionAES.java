package client;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class EncryptionAES {
    private final SecretKeySpec secretKeySpec;
    private final SecretKeyFactory secretKeyFactory;
    private final int IV_LENGTH = 16;
    private final String secretKeyAlgorithm = "PBKDF2WithHmacSHA256";
    private final String cipherAlgorithm = "AES/CBC/PKCS5Padding";
    private final String encryptionAlgorithm = "AES";
    private final int keyLength = 256;
    private final int iterationCount = 65536;
    private final String salt = "123456789123";

    public EncryptionAES(String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.secretKeyFactory = SecretKeyFactory.getInstance(secretKeyAlgorithm);
        this.secretKeySpec = createSecretKey(secretKeyFactory, password);
    }

    public String encrypt(String message) {
        SecretKeySpec secretKeySpec = this.secretKeySpec;
        return doEncrypt(message, secretKeySpec);
    }

    public String encrypt(String message, String password) {
        SecretKeySpec secretKeySpec = getSecretKeySpec(password);
        return doEncrypt(message, secretKeySpec);
    }

    private Cipher createCipher(SecretKeySpec secretKeySpec, int encryptMode, IvParameterSpec ivParameterSpec) {
        try {
            Cipher cipher = Cipher.getInstance(cipherAlgorithm);
            cipher.init(encryptMode, secretKeySpec, ivParameterSpec);
            return cipher;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException e) {
            throw new IllegalStateException(e);
        }
    }

    private SecretKeySpec createSecretKey(SecretKeyFactory factory, String password) throws InvalidKeySpecException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), iterationCount, keyLength);
        SecretKey secretKey = factory.generateSecret(spec);
        return new SecretKeySpec(secretKey.getEncoded(), encryptionAlgorithm);
    }

    private SecretKeySpec getSecretKeySpec(String password) {
        SecretKeySpec secretKeySpec;
        try {
            secretKeySpec = createSecretKey(secretKeyFactory, password);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return secretKeySpec;
    }

    private String doEncrypt(String message, SecretKeySpec secretKeySpec) {
        if (message == null) {
            return null;
        }
        try {
            IvParameterSpec ivParameterSpec = randomIV();
            Cipher cipher = createEncryptionCipher(secretKeySpec, ivParameterSpec);
            byte[] cipherTextInByteArr = cipher.doFinal(message.getBytes(StandardCharsets.UTF_8));
            byte[] ivAndCipherText = joinByteArray(ivParameterSpec.getIV(), cipherTextInByteArr);
            return Base64.getEncoder().encodeToString(ivAndCipherText);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    private byte[] joinByteArray(byte[] byte1, byte[] byte2) {

        return ByteBuffer.allocate(byte1.length + byte2.length)
                .put(byte1)
                .put(byte2)
                .array();

    }

    private IvParameterSpec randomIV() {
        SecureRandom randomSecureRandom = new SecureRandom();
        byte[] iv = new byte[IV_LENGTH];
        randomSecureRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private Cipher createEncryptionCipher(SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) {
        return createCipher(secretKeySpec, Cipher.ENCRYPT_MODE, ivParameterSpec);
    }

    private Cipher createDecryptionCipher(SecretKeySpec secretKeySpec, IvParameterSpec ivParameterSpec) {
        return createCipher(secretKeySpec, Cipher.DECRYPT_MODE, ivParameterSpec);
    }


    public String decrypt(String encryptedMessage) {
        SecretKeySpec secretKeySpec = this.secretKeySpec;
        return doDecrypt(encryptedMessage, secretKeySpec);
    }

    public String decrypt(String encryptedMessage, String password) {
        SecretKeySpec secretKeySpec = getSecretKeySpec(password);

        return doDecrypt(encryptedMessage, secretKeySpec);
    }

    private String doDecrypt(String encryptedMessage, SecretKeySpec secretKeySpec) {
        if (encryptedMessage == null) {
            return null;
        }
        try {
            byte[] ivAndCipherText = Base64.getDecoder().decode(encryptedMessage);
            byte[] iv = new byte[IV_LENGTH];
            byte[] cipherText = new byte[ivAndCipherText.length - IV_LENGTH];
            System.arraycopy(ivAndCipherText, 0, iv, 0, iv.length);
            System.arraycopy(ivAndCipherText, iv.length, cipherText, 0, cipherText.length);
            Cipher cipher = createDecryptionCipher(secretKeySpec, new IvParameterSpec(iv));
            byte[] plainTextInByteArr = cipher.doFinal(cipherText);
            return new String(plainTextInByteArr, StandardCharsets.UTF_8);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
