package net.craswell.common.encryption;

/**
 * Models a passphrase provider.
 * 
 * @author scraswell@gmail.com
 *
 */
public interface PassphraseProvider {
  /**
   * Gets the passphrase from which an encryption key would be derived.
   * 
   * @return The passphrase from which an encryption key would be derived.
   */
  public String getPassphrase();
}
