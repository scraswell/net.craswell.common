package net.craswell.common.encryption;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

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
public final class AesToolImpl
    implements AesTool {
  /**
   * The encryption cipher.
   */
  private static final String CIPHER = "AES";

  /**
   * The encryption cipher specification.
   */
  private static final String CIPHER_SPEC = "AES/CBC/PKCS5Padding";
  
  /**
   * The secret key factory algorithm.
   */
  private static final String SECRET_KEY_FACTORY_ALGORITHM = "PBKDF2WithHmacSHA256";

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
   * @throws AesToolException Thrown when the instantiation fails.
   */
  public AesToolImpl()
      throws AesToolException {
    try {
      this.secretKeyFactory = SecretKeyFactory
          .getInstance(AesToolImpl.SECRET_KEY_FACTORY_ALGORITHM);
    } catch (NoSuchAlgorithmException e) {
      String exceptionMessage = String.format(
          "An exception occurred while attemption to initialize the AesTool with the %1$s algorithm.",
          AesToolImpl.SECRET_KEY_FACTORY_ALGORITHM);

      throw new AesToolException(
          exceptionMessage,
          e);
    }
  }

  /* (non-Javadoc)
   * @see net.craswell.common.encryption.AesTool#encodeObject(net.craswell.common.encryption.EncryptedObject)
   */
  public final String encodeObject(EncryptedObject encryptedObject) {
    if (encryptedObject == null
        || encryptedObject.getSalt() == null
        || encryptedObject.getCiphertext() == null
        || encryptedObject.getInitializationVector() == null) {
      throw new IllegalArgumentException("The encrypted object was null or missing information.");
    }

    Encoder encoder = Base64.getEncoder();
    StringBuilder secureStringBuilder = new StringBuilder();

    secureStringBuilder.append(encoder.encodeToString(encryptedObject.getInitializationVector()));
    secureStringBuilder.append("%");
    secureStringBuilder.append(encoder.encodeToString(encryptedObject.getSalt()));
    secureStringBuilder.append("%");
    secureStringBuilder.append(encoder.encodeToString(encryptedObject.getCiphertext()));

    return secureStringBuilder
        .toString();
  }

  /* (non-Javadoc)
   * @see net.craswell.common.encryption.AesTool#decodeObject(java.lang.String)
   */
  public final EncryptedObject decodeObject(String base64EncodedEncryptedObject) {
    String[] secureObjectParts = base64EncodedEncryptedObject.split("%");
    Decoder decoder = Base64.getDecoder();

    byte[] initializationVector = decoder.decode(secureObjectParts[0]);
    byte[] salt = decoder.decode(secureObjectParts[1]);
    byte[] cipherText = decoder.decode(secureObjectParts[2]);
    
    EncryptedObject encryptedObject = new EncryptedObject();
    encryptedObject.setSalt(salt);
    encryptedObject.setInitializationVector(initializationVector);
    encryptedObject.setCiphertext(cipherText);

    return encryptedObject;
  }
  
  /* (non-Javadoc)
   * @see net.craswell.common.encryption.AesTool#encrypt(byte[], java.lang.String)
   */
  @Override
  public EncryptedObject encrypt(
      byte[] input,
      String passPhrase) throws AesToolException {

    byte[] salt = AesToolImpl.generateSalt();

    SecretKey secretKey = this.deriveKey(
        salt,
        passPhrase);

    Cipher cipher = this.determineCipher();

    AlgorithmParameters params = cipher.getParameters();

    IvParameterSpec ivParams = this.determineIVParameterSpec(params);

    this.initializeCipher(
        secretKey,
        cipher,
        ivParams,
        Cipher.ENCRYPT_MODE);

    return createEncryptedObject(
        input,
        salt,
        cipher,
        ivParams);
  }

  /* (non-Javadoc)
   * @see net.craswell.common.encryption.AesTool#decrypt(net.craswell.common.encryption.EncryptedObject, java.lang.String)
   */
  @Override
  public byte[] decrypt(
      EncryptedObject encryptedObject,
      String passPhrase) throws AesToolException {

    if (encryptedObject == null
        || encryptedObject.getSalt() == null
        || encryptedObject.getCiphertext() == null
        || encryptedObject.getInitializationVector() == null) {
      throw new IllegalArgumentException("The encrypted object was null or missing information.");
    }

    SecretKey secretKey = this.deriveKey(
        encryptedObject.getSalt(),
        passPhrase);

    Cipher cipher = this.determineCipher();

    IvParameterSpec ivSpec = new IvParameterSpec(
        encryptedObject.getInitializationVector());

    this.initializeCipher(
        secretKey,
        cipher,
        ivSpec,
        Cipher.DECRYPT_MODE);

    byte[] decryptedBytes = this.decryptCipherText(
        encryptedObject,
        cipher);

    return decryptedBytes;
  }
  

  /**
   * Generates a random salt value.
   * 
   * @return A random salt value.
   */
  private static byte[] generateSalt() {
    byte[] salt = new byte[SALT_SIZE];

    SECURE_RANDOM.nextBytes(salt);

    return salt;
  }

  /**
   * Attempts to decrypt the ciphertext given the encrypted object and the cipher.
   * 
   * @param encryptedObject The encrypted object.
   * @param cipher The cipher used for encryption.
   * 
   * @return The decrypted ciphertext.
   * 
   * @throws AesToolException Thrown when the process to decrypt the ciphertext fails.
   */
  private byte[] decryptCipherText(
      EncryptedObject encryptedObject,
      Cipher cipher)
      throws AesToolException {
    byte[] decryptedBytes;

    try {
      decryptedBytes = cipher.doFinal(encryptedObject.getCiphertext());
    } catch (IllegalBlockSizeException e) {
      throw new AesToolException(
          "An exception occurred while attempting to decrypt the ciphertext.",
          e);
    } catch (BadPaddingException e) {
      throw new AesToolException(
          "An exception occurred while attempting to decrypt the ciphertext.  It is likely that the passphrase given is not the same as the passphrase that was used to originally encrypt the data.",
          e);
    }

    return decryptedBytes;
  }

  /**
   * Encrypts the input data and returns an encrypted object.
   * 
   * @param input The input data to be encrypted.
   * @param salt The salt that was combined with the passphrase to derive the secret key.
   * @param cipher The cipher initialized with the secret key and IV for encryption.
   * @param ivParams The IV parameter spec.
   * @return An encrypted object.
   * 
   * @throws AesToolException Thrown when the process to encrypt the data fails.
   */
  private EncryptedObject createEncryptedObject(
      byte[] input,
      byte[] salt,
      Cipher cipher,
      IvParameterSpec ivParams)
          throws AesToolException {
    byte[] cipherText;

    try {
      cipherText = cipher.doFinal(input);
    } catch (
        IllegalBlockSizeException
        | BadPaddingException e) {
      throw new AesToolException(
          "An exception occurred during the process to encrypt the data.",
          e);
    }

    EncryptedObject encryptedObject = new EncryptedObject();
    encryptedObject.setSalt(salt);
    encryptedObject.setInitializationVector(ivParams.getIV());
    encryptedObject.setCiphertext(cipherText);

    return encryptedObject;
  }

  /**
   * Determines the IV parameter spec from the algorithm parameters.
   * 
   * @param params The algorithm parameters.
   * @return The IV parameter spec.
   * 
   * @throws AesToolException Thrown when the process to get the IV parameter spec fails.
   */
  private IvParameterSpec determineIVParameterSpec(AlgorithmParameters params)
      throws AesToolException {
    IvParameterSpec ivParams;

    try {
      ivParams = params
          .getParameterSpec(IvParameterSpec.class);
    } catch (InvalidParameterSpecException e) {
      throw new AesToolException(
          "An exception occurred while attempting to obtain the initialization vector parameters.",
          e);
    }
    return ivParams;
  }

  /**
   * Derives a key to be used for AES-256-CBC encryption, given a pass phrase.
   * 
   * @param salt The salt used for encryption.
   * @param passPhrase The pass phrase.
   * @return The symmetric key.
   * 
   * @throws AesToolException 
   */
  private SecretKey deriveKey(
      byte[] salt,
      String passPhrase) throws AesToolException {

    KeySpec keySpec = new PBEKeySpec(
        passPhrase.toCharArray(),
        salt,
        KEY_DERIVATION_ITERATIONS,
        KEY_SIZE);

    SecretKeySpec secretKeySpec;

    try {
      secretKeySpec = new SecretKeySpec(
          this.secretKeyFactory.generateSecret(keySpec).getEncoded(),
          CIPHER);
    } catch (InvalidKeySpecException e) {
      throw new AesToolException(
          "An exception occurred while attempting to derive the secret key from the salt and passphrase.",
          e);
    }

    return secretKeySpec;
  }

  /**
   * Initializes the cipher for processing.
   * 
   * @param secretKey The secret key to be used by the cipher.
   * @param cipher The cipher to be used.
   * @param ivSpec The initialization vector to be used.
   * @param mode The mode in which the cipher should operate.
   * 
   * @throws AesToolException Thrown when the cipher fails to be initialized.
   */
  private void initializeCipher(
      SecretKey secretKey,
      Cipher cipher,
      IvParameterSpec ivSpec,
      int mode)
          throws AesToolException {
    try {
      cipher.init(
          mode,
          secretKey,
          ivSpec);
    } catch (
        InvalidKeyException
        | InvalidAlgorithmParameterException e) {
      throw new AesToolException(
          "An exception occurred while trying to initialize the cipher.",
          e);
    }
  }

  /**
   * Determines the cipher to be used.
   * 
   * @return The encryption cipher.
   * 
   * @throws AesToolException Thrown when the cipher instance cannot be obtained.
   */
  private Cipher determineCipher()
      throws AesToolException {
    Cipher cipher;

    try {
      cipher = Cipher.getInstance(CIPHER_SPEC);
    } catch (
        NoSuchAlgorithmException
        | NoSuchPaddingException e) {
      throw new AesToolException(
          "An exception occurred while trying to determine the cipher specification.",
          e);
    }

    return cipher;
  }
}
