package com.threeshell;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.net.*;

public class HubSock {

  private static final String SERVER_PASSWORD = "deepnode";

  protected static SSLSocketFactory getSSLSocketFactory ( String clientPass, String path )
                        throws IOException, GeneralSecurityException {
    TrustManager[] tms = getTrustManagers(path + "hubclient.jks", clientPass);
    KeyManager[] kms = getKeyManagers(path + "hubclient.jks", clientPass);

    SSLContext context = SSLContext.getInstance( "SSL" );
    context.init( kms, tms, null );

    SSLSocketFactory ssf = context.getSocketFactory();
    return ssf;
  }

  protected static SSLServerSocketFactory getServerSocketFactory ( String path ) throws IOException, GeneralSecurityException {
    TrustManager[] tms = getTrustManagers(path + "hubserver.jks", SERVER_PASSWORD);
    KeyManager[] kms = getKeyManagers(path + "hubserver.jks", SERVER_PASSWORD);

    SSLContext context = SSLContext.getInstance( "SSL" );
    context.init( kms, tms, null );

    SSLServerSocketFactory ssf = context.getServerSocketFactory();
    return ssf;
  }

  protected static TrustManager[] getTrustManagers(String storeName, String pass) throws IOException, GeneralSecurityException {
    String alg = TrustManagerFactory.getDefaultAlgorithm();
    TrustManagerFactory tmFact = TrustManagerFactory.getInstance( alg );

    FileInputStream fis = new FileInputStream(new File(storeName));
    KeyStore ks = KeyStore.getInstance( "jks" );
    ks.load( fis, pass.toCharArray() );
    fis.close();

    tmFact.init( ks );
    TrustManager[] tms = tmFact.getTrustManagers();
    return tms;
  }

  protected static KeyManager[] getKeyManagers(String storeName, String pass) throws IOException, GeneralSecurityException {
    String alg = KeyManagerFactory.getDefaultAlgorithm();
    KeyManagerFactory kmFact = KeyManagerFactory.getInstance( alg );

    FileInputStream fis = new FileInputStream(new File(storeName));
    KeyStore ks = KeyStore.getInstance( "jks" );
    ks.load( fis, pass.toCharArray() );
    fis.close();

    kmFact.init( ks, pass.toCharArray() );
    KeyManager[] kms = kmFact.getKeyManagers();
    return kms;
  }

  public static Socket getSocket ( String host, int port, String pass,
                                   String path ) throws IOException, GeneralSecurityException {
    SSLSocketFactory sslSocketFactory = getSSLSocketFactory(pass, path);
    SSLSocket socket = (SSLSocket)sslSocketFactory.createSocket(host, port);
    socket.setSoTimeout(5000);
    System.out.println( "Connecting to "
          + socket.getRemoteSocketAddress().toString() + " : "
          + socket.getPort() );
    System.out.println( "Is Connected? " + socket.isConnected() );
    socket.startHandshake();
    return socket;
  }

  public static ServerSocket getServerSocket ( int port, String path ) throws IOException, GeneralSecurityException {
    SSLServerSocketFactory ssf = getServerSocketFactory(path); 
    SSLServerSocket sss = (SSLServerSocket) ssf.createServerSocket(port);
    sss.setNeedClientAuth(true);
    return sss;
  }
}
