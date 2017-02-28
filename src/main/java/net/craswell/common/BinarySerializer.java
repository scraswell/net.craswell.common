package net.craswell.common;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.util.Base64;

/**
 * Serializes and deserializes objects to and from binary.
 * 
 * @author scraswell@gmail.com
 *
 */
public final class BinarySerializer {
  /**
   * Deserializes an object from base64 encoded binary data.
   * 
   * @param base64String The base64 encoded binary data.
   * 
   * @return The deserialized object.
   * 
   * @throws ClassNotFoundException Thrown when unable to find the class from which the serialized
   *         object was originally instantiated.
   * @throws IOException Thrown when unable to read the data from it's source.
   */
  public static final Object deserializeFromString(String base64String)
      throws ClassNotFoundException,
      IOException {

    return deserializeObject(
        Base64.getDecoder().decode(base64String));
  }

  /**
   * Deserializes from a byte array to an object.
   * 
   * @param objectBytes The serialized bytes.
   * @return The deserialized object.
   * @throws ClassNotFoundException Thrown when unable to find the class from which the serialized
   *         object was originally instantiated.
   * @throws IOException Thrown when unable to read the data from it's source.
   */
  public static final Object deserializeObject(byte[] objectBytes)
      throws IOException,
      ClassNotFoundException {

    ObjectInput objectInput = null;

    try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objectBytes)) {
      objectInput = new ObjectInputStream(byteArrayInputStream);
      Object object = objectInput.readObject();

      return object;
    } finally {
      if (objectInput != null) {
        objectInput.close();
        objectInput = null;
      }
    }
  }

  /**
   * Serializes an object to a base64 encoded byte array.
   * 
   * @param object The object to be serialized.
   * @return The base64 encoded byte array.
   * 
   * @throws IOException Thrown when unable to write the object out to the byte array.
   */
  public static final String serializeToString(Object object)
      throws IOException {

    return Base64.getEncoder()
        .encodeToString(serializeObject(object));
  }

  /**
   * Serializes an object to a byte array.
   * 
   * @param object The object to be serialized.
   * @return The byte array to which the object was serialized.
   * 
   * @throws IOException Thrown when unable to write the object out to the byte array.
   */
  public static final byte[] serializeObject(Object object)
      throws IOException {

    ObjectOutput oo = null;

    try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
      oo = new ObjectOutputStream(byteArrayOutputStream);
      oo.writeObject(object);
      oo.flush();

      return byteArrayOutputStream.toByteArray();
    } finally {
      if (oo != null) {
        oo.close();
        oo = null;
      }
    }
  }
}
