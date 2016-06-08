/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.codelibs.elasticsearch.repository.ssh.utils;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.elasticsearch.common.blobstore.BlobPath;

public class CryptoUtils {
  public static final String ALGORITHM = "AES";
  public static final String ENCRYPTION_MODE = "AES/CBC/PKCS5PADDING";
  public static final int KEY_LENGTH = 128;

  public static byte[] getRandomKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
      keyGenerator.init(KEY_LENGTH);
      byte[] key = keyGenerator.generateKey().getEncoded();
      return key;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  public static Cipher getEncryptCipher(byte[] key, byte[] iv) {
    try {
      Cipher cipher = Cipher.getInstance(ENCRYPTION_MODE);
      SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
      cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
      return cipher;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (NoSuchPaddingException e) {
      throw new RuntimeException(e);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException("illegal encrypt key", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("illegal iv", e);
    }
  }

  public static Cipher getDecryptCipher(byte[] key, byte[] iv) {
    try {
      Cipher cipher = Cipher.getInstance(ENCRYPTION_MODE);
      SecretKeySpec keySpec = new SecretKeySpec(key, ALGORITHM);
      cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
      return cipher;
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    } catch (NoSuchPaddingException e) {
      throw new RuntimeException(e);
    } catch (InvalidKeyException e) {
      throw new IllegalArgumentException("illegal encrypt key", e);
    } catch (InvalidAlgorithmParameterException e) {
      throw new IllegalArgumentException("illegal iv", e);
    }
  }

  public static byte[] encrypt(byte[] plain, byte[] key, byte[] iv) {
    Cipher cipher = getEncryptCipher(key, iv);
    try {
      byte[] encrypted = cipher.doFinal(plain);
      return encrypted;
    } catch (IllegalBlockSizeException e) {
      throw new RuntimeException(e);
    } catch (BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] encrypt(String plain, byte[] key, byte[] iv) {
    if (plain == null) {
      throw new IllegalArgumentException("input string cannot be null");
    }
    try {
      return encrypt(plain.getBytes("UTF-8"), key, iv);
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] decrypt(byte[] plain, byte[] key, byte[] iv) {
    Cipher cipher = getDecryptCipher(key, iv);
    try {
      byte[] decrypted = cipher.doFinal(plain);
      return decrypted;
    } catch (IllegalBlockSizeException e) {
      throw new RuntimeException(e);
    } catch (BadPaddingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] decrypt(String plain, byte[] key, byte[] iv) {
    if (plain == null) {
      throw new IllegalArgumentException("input string cannot be null");
    }
    try {
      return decrypt(plain.getBytes("UTF-8"), key, iv);
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String encryptHex(byte[] plain, byte[] key, byte[] iv) {
    return encodeHexString(encrypt(plain, key, iv));
  }

  public static String encryptBase64(byte[] plain, byte[] key, byte[] iv) {
    return encodeBase64(encrypt(plain, key, iv));
  }

  public static byte[] decryptHex(String ciphertext, byte[] key, byte[] iv) {
    return decrypt(decodeHex(ciphertext), key, iv);
  }

  public static byte[] decryptBase64(String ciphertext, byte[] key, byte[] iv) {
    return decrypt(decodeBase64(ciphertext), key, iv);
  }

  public static String encodeHexString(byte[] content) {
    return Hex.encodeHexString(content);
  }

  public static byte[] decodeHex(byte[] hexContent) {
    Hex hex = new Hex();
    try {
      return hex.decode(hexContent);
    } catch (DecoderException e) {
      throw new IllegalArgumentException(e);
    }
  }

  public static byte[] decodeHex(String hexString) {
    Hex hex = new Hex();
    try {
      return hex.decode(hexString.getBytes("UTF-8"));
    } catch (DecoderException e) {
      throw new IllegalArgumentException(e);
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String encodeBase64(byte[] content) {
    return Base64.encodeBase64URLSafeString(content);
  }

  public static String encodeBase64(String content) {
    try {
      return Base64.encodeBase64URLSafeString(content.getBytes("UTF-8"));
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static byte[] decodeBase64(String content) {
    return Base64.decodeBase64(content);
  }

  public static String decodeBase64ToString(String content) {
    try {
      return new String(decodeBase64(content), "UTF-8");
    } catch (UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public static String buildCryptPath(BlobPath blobPath, byte[] key, byte[] iv) {
    StringBuilder sb = new StringBuilder();
    for (String path : blobPath.toArray()) {
      sb.append(encryptBase64(path.getBytes(), key, iv));
      sb.append("/");
    }
    if (blobPath.toArray().length > 0) {
      sb.setLength(sb.length() - 1);
    }
    return sb.toString();
  }

}
