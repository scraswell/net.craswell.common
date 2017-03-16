package net.craswell.common;

/**
 * Exceptions thrown from the BinarySerializer.
 * 
 * @author scraswell@gmail.com
 *
 */
public class BinarySerializerException
    extends Exception {
  /**
   * The serial version UID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Initializes a new instance of the BinarySerializerException class.
   */
  public BinarySerializerException() {
    super();
  }

  /**
   * Initializes a new instance of the BinarySerializerException class.
   * 
   * @param message The exception message.
   */
  public BinarySerializerException(String message) {
    super(message);
  }

  /**
   * Initializes a new instance of the BinarySerializerException class.
   * 
   * @param message The exception message.
   * @param innerException The inner exception.
   */
  public BinarySerializerException(
      String message,
      Exception innerException) {
    super(message, innerException);
  }
}
