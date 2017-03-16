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
 * Provides functionality to serialize and de-serialize objects to and from binary.
 * 
 * @author scraswell@gmail.com
 *
 */
public final class BinarySerializer {
  /**
   * De-serializes an object from base64 encoded binary data.
   * 
   * @param base64String The base64 encoded binary data.
   * 
   * @return The de-serialized object.
   * @throws BinarySerializerException 
   * 
   * @throws ClassNotFoundException Thrown when unable to find the class from which the serialized
   *         object was originally instantiated.
   * @throws IOException Thrown when unable to read the data from it's source.
   */
  public static final Object deserializeFromString(String base64String)
      throws BinarySerializerException {

      return BinarySerializer.deserializeObject(
          Base64.getDecoder().decode(base64String));
  }

  /**
   * De-serializes from a byte array to an object.
   * 
   * @param objectBytes The serialized bytes.
   * @return The de-serialized object.
   *
   * @throws BinarySerializerException When the process to deserialize an object fails. 
   */
  public static final Object deserializeObject(byte[] objectBytes)
      throws BinarySerializerException {

    ObjectInput objectInput = null;

    try (ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(objectBytes)) {

      objectInput = new ObjectInputStream(byteArrayInputStream);
      Object object = objectInput.readObject();

      return object;

    } catch (
        IOException
        | ClassNotFoundException e) {

      throw new BinarySerializerException(
          "An exception occurred when deserialize the object.",
          e);

    } finally {

      if (objectInput != null) {
        try {
          objectInput.close();
        } catch (IOException e) {
          throw new BinarySerializerException(
              "An exception occurred when attempting to close the ObjectInputStream.",
              e);
        }
        objectInput = null;
      }

    }
  }

  /**
   * Serializes an object to a base64 encoded byte array.
   * 
   * @param object The object to be serialized.
   * 
   * @return The base64 encoded byte array.
   * @throws BinarySerializerException 
   */
  public static final String serializeToString(Object object)
      throws BinarySerializerException {

    return Base64.getEncoder().encodeToString(
        BinarySerializer.serializeObject(object));
  }

  /**
   * Serializes an object to a byte array.
   * 
   * @param object The object to be serialized.
   * @return The byte array to which the object was serialized.
   * @throws BinarySerializerException 
   * 
   * @throws IOException Thrown when unable to write the object out to the byte array.
   */
  public static final byte[] serializeObject(Object object)
      throws BinarySerializerException {

    ObjectOutput oo = null;

    try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {

      oo = new ObjectOutputStream(byteArrayOutputStream);
      oo.writeObject(object);
      oo.flush();

      return byteArrayOutputStream.toByteArray();

    } catch (IOException e) {

      throw new BinarySerializerException(
          "An exception occurred when deserialize the object.",
          e);

    } finally {
      if (oo != null) {
        try {
          oo.close();
        } catch (IOException e) {
          throw new BinarySerializerException(
              "An exception occurred when attempting to close the ObjectOutputStream.",
              e);
        }
        oo = null;
      }
    }
  }
}
