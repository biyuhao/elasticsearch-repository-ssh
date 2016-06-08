/*
 * Licensed to Elasticsearch under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright ownership.
 * Elasticsearch licenses this file to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at http://www.apache.org/licenses/LICENSE-2.0 Unless required by applicable law or agreed
 * to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 */

package org.codelibs.elasticsearch.repository.ssh.utils;

public class SshConfig {
  private String host;
  private int port;
  private String username;
  private String password;
  private String knownHosts;
  private boolean ignoreHostKeyChecking;
  private String privateKey;
  private String passphrase;
  private String location;
  private boolean isEncrypt;
  private byte[] key;
  private byte[] iv;

  public String getHost() {
    return host;
  }

  public void setHost(String host) {
    this.host = host;
  }

  public int getPort() {
    return port;
  }

  public void setPort(int port) {
    this.port = port;
  }

  public String getUsername() {
    return username;
  }

  public void setUsername(String username) {
    this.username = username;
  }

  public String getPassword() {
    return password;
  }

  public String getPassphrase() {
    return passphrase;
  }

  public void setPassphrase(String passphrase) {
    this.passphrase = passphrase;
  }

  public void setPassword(String password) {
    this.password = password;
  }

  public String getKnownHosts() {
    return knownHosts;
  }

  public void setKnownHosts(String knownHosts) {
    this.knownHosts = knownHosts;
  }

  public boolean isIgnoreHostKeyChecking() {
    return ignoreHostKeyChecking;
  }

  public void setIgnoreHostKeyChecking(boolean ignoreHostKeyChecking) {
    this.ignoreHostKeyChecking = ignoreHostKeyChecking;
  }

  public String getPrivateKey() {
    return privateKey;
  }

  public void setPrivateKey(String privateKey) {
    this.privateKey = privateKey;
  }

  public String getLocation() {
    return location;
  }

  public void setLocation(String location) {
    this.location = location;
  }

  public boolean isEncrypt() {
    return isEncrypt;
  }

  public void setEncrypt(boolean encrypt) {
    isEncrypt = encrypt;
  }

  public byte[] getKey() {
    return key;
  }

  public void setKey(byte[] key) {
    this.key = key;
  }

  public byte[] getIv() {
    return iv;
  }

  public void setIv(byte[] iv) {
    this.iv = iv;
  }
}
