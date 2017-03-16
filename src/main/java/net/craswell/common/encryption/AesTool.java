package net.craswell.common.encryption;

/**
 * Describes the members available to implementations of the AesTool.
 * 
 * @author scraswell@gmail.com
 *
 */
public interface AesTool {

  /**
   * Encrypts the given bytes using a pass phrase to derive a key.
   * 
   * @param input The input bytes.
   * @param passPhrase The pass phrase.
   * @return An encrypted object.
   * 
   * @throws AesToolException Thrown when the encryption process fails.
   */
  EncryptedObject encrypt(
      byte[] input,
      String passPhrase)
          throws AesToolException;

  /**
   * Reverses encryption.
   * 
   * @param encryptedObject The encrypted object.
   * @param passPhrase The pass phrase used to derive the encryption key.
   * @return The object bytes after encryption is reversed.
   * 
   * @throws AesToolException Thrown when the encryption reversal fails.
   */
  byte[] decrypt(
      EncryptedObject encryptedObject,
      String passPhrase)
          throws AesToolException;

  /**
   * Encodes an encrypted object to a Base64 encoded string.
   * 
   * @param encryptedObject The encrypted object to be encoded.
   * @return The base64 string encoded encrypted object.
   */
  String encodeObject(EncryptedObject encryptedObject);

  /**
   * Decodes an encrypted object from a Base64 encoded string.
   * 
   * @param base64EncodedEncryptedObject The Base64 string representation of the encrypted object.
   * 
   * @return The encrypted object as decoded from the Base64 string.
   */
  EncryptedObject decodeObject(String base64EncodedEncryptedObject);

}
