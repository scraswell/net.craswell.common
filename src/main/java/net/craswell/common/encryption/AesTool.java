package net.craswell.common.encryption;

import java.io.UnsupportedEncodingException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A helper tool providing AES-256-CBC encryption.
 * 
 * Requires unlimited strength JCE policy files.
 * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
 * 
 * @author scraswell@gmail.com
 *
 */
public final class AesTool {
  /**
   * The encryption cipher.
   */
  private static final String CIPHER = "AES";

  /**
   * The encryption cipher specification.
   */
  private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";

  /**
   * The size of the derived key.
   */
  private static final int KEY_SIZE = 256;

  /**
   * The salt size.
   */
  private static final int SALT_SIZE = 8;

  /**
   * The number of key derivation iterations.
   */
  private static final int KEY_DERIVATION_ITERATIONS = 65535;

  /**
   * A CSPRNG implementation.
   */
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  /**
   * The secret key factory.
   */
  private final SecretKeyFactory secretKeyFactory;

  /**
   * Initializes a new instance of the AesTool encryption tool.
   * 
   * @throws NoSuchAlgorithmException
   */
  public AesTool()
      throws NoSuchAlgorithmException {
    this.secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
  }

  /**
   * Reverses encryption.
   * 
   * @param encryptedObject The encrypted object.
   * @param passPhrase The pass phrase used to derive the encryption key.
   * @return The object bytes after encryption is reversed.
   * 
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   * @throws InvalidAlgorithmParameterException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   */
  public byte[] decrypt(
      EncryptedObject encryptedObject,
      String passPhrase)
      throws InvalidKeySpecException,
      InvalidKeyException,
      InvalidAlgorithmParameterException,
      IllegalBlockSizeException,
      BadPaddingException,
      NoSuchAlgorithmException,
      NoSuchPaddingException {

    if (encryptedObject == null
        || encryptedObject.getSalt() == null
        || encryptedObject.getCiphertext() == null
        || encryptedObject.getInitializationVector() == null) {
      throw new IllegalArgumentException("The encrypted object was null or missing information.");
    }

    SecretKey secretKey = this.deriveKey(
        encryptedObject.getSalt(),
        passPhrase);

    Cipher cipher = Cipher.getInstance(CIPHER_SPEC);

    IvParameterSpec ivSpec = new IvParameterSpec(
        encryptedObject.getInitializationVector());

    cipher.init(
        Cipher.DECRYPT_MODE,
        secretKey,
        ivSpec);

    return cipher.doFinal(encryptedObject.getCiphertext());
  }

  /**
   * Encrypts the given bytes using a pass phrase to derive a key.
   * 
   * @param input The input bytes.
   * @param passPhrase The pass phrase.
   * @return An encrypted object.
   * 
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   * @throws InvalidParameterSpecException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws UnsupportedEncodingException
   * @throws NoSuchAlgorithmException
   * @throws NoSuchPaddingException
   * @throws InvalidAlgorithmParameterException
   */
  public EncryptedObject encrypt(
      byte[] input,
      String passPhrase)
      throws InvalidKeySpecException,
      InvalidKeyException,
      InvalidParameterSpecException,
      IllegalBlockSizeException,
      BadPaddingException,
      UnsupportedEncodingException,
      NoSuchAlgorithmException,
      NoSuchPaddingException,
      InvalidAlgorithmParameterException {

    EncryptedObject encryptedObject = new EncryptedObject();

    encryptedObject.setSalt(this.generateSalt());

    SecretKey encryptionKey = deriveKey(
        encryptedObject.getSalt(),
        passPhrase);

    Cipher cipher = Cipher
        .getInstance(CIPHER_SPEC);

    AlgorithmParameters params = cipher
        .getParameters();

    IvParameterSpec ivParams = params
        .getParameterSpec(IvParameterSpec.class);

    encryptedObject
        .setInitializationVector(ivParams.getIV());

    cipher.init(
        Cipher.ENCRYPT_MODE,
        encryptionKey,
        ivParams);

    encryptedObject.setCiphertext(cipher.doFinal(input));

    return encryptedObject;
  }

  /**
   * Derives a key to be used for AES-256-CBC encryption, given a pass phrase.
   * 
   * @param salt The salt used for encryption.
   * @param passPhrase The pass phrase.
   * @return The symmetric key.
   * 
   * @throws InvalidKeySpecException
   */
  private SecretKey deriveKey(
      byte[] salt,
      String passPhrase)
      throws InvalidKeySpecException {

    KeySpec keySpec = new PBEKeySpec(
        passPhrase.toCharArray(),
        salt,
        KEY_DERIVATION_ITERATIONS,
        KEY_SIZE);

    return new SecretKeySpec(
        this.secretKeyFactory.generateSecret(keySpec).getEncoded(),
        CIPHER);
  }

  /**
   * Generates a random salt value.
   * 
   * @return A random salt value.
   */
  private byte[] generateSalt() {
    byte[] salt = new byte[SALT_SIZE];

    SECURE_RANDOM.nextBytes(salt);

    return salt;
  }
}
