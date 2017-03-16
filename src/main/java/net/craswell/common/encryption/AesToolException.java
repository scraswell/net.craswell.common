package net.craswell.common.encryption;

/**
 * Exceptions thrown by the AesTool.
 * 
 * @author scraswell@gmail.com.
 *
 */
public class AesToolException
  extends Exception {
  /**
   * The serial version UID.
   */
  private static final long serialVersionUID = 1L;

  /**
   * Initializes a new instance of the AesToolException class.
   * 
   * @param message The exception message.
   * @param innerException The inner exception.
   */
  public AesToolException() {
    super();
  }

  /**
   * Initializes a new instance of the AesToolException class.
   * 
   * @param message The exception message.
   * @param innerException The inner exception.
   */
  public AesToolException(String message) {
    super(message);
  }

  /**
   * Initializes a new instance of the AesToolException class.
   * 
   * @param message The exception message.
   * @param innerException The inner exception.
   */
  public AesToolException(
      String message,
      Exception innerException) {
    super(message, innerException);
  }
}
