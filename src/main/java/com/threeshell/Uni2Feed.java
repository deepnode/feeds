package com.threeshell;

import java.io.*;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.channels.FileChannel;
import java.nio.ByteBuffer;

public class Uni2Feed {

  private FileChannel chan;
  private String fileName;

  public Uni2Feed ( String fileName ) {
    this.fileName = fileName;
  }

  public static void main ( String[] args ) {
    try {
      Uni2Feed u2f = new Uni2Feed(args[0]);
      u2f.feed();
    }
    catch ( Exception e ) {
      System.out.println("error feeding: " + e);
      e.printStackTrace(System.out);
    }
  }

  public void feed () throws IOException, InterruptedException, UnknownHostException {
    FileInputStream fis = new FileInputStream(fileName);
    chan = fis.getChannel();
    ByteBuffer headBuf = ByteBuffer.allocate(8);
    int headCount = 0;
    while ( (headCount = chan.read(headBuf)) != -1 ) {
      if ( headCount == 0 ) {
        System.out.println("got nothing");
        Thread.sleep(2000);
      }
      else {
        long type = get4Long(headBuf, 0);
        long length = get4Long(headBuf, 4);
        headBuf.rewind();
        System.out.println("type: " + type + ", length: " + length); 
        ByteBuffer bodyBuf = ByteBuffer.allocate((int)length);
        int bodyCount = chan.read(bodyBuf);     
        System.out.println("   body read: " + bodyCount);
        bodyBuf.rewind();

        if ( type == 7 )
          feedEvent(bodyBuf);
        else if ( type == 2 )
          feedIP4(bodyBuf);
      }
    }
    chan.close();
    fis.close();
  }

  private void feedEvent ( ByteBuffer bodyBuf ) throws UnknownHostException {
    String sourceIp = getIp(bodyBuf, 36);
    String destIp = getIp(bodyBuf, 40);
    int sourcePort = get2Int(bodyBuf, 44);
    int destPort = get2Int(bodyBuf, 46);
    int protocol = get1Int(bodyBuf, 48);
    System.out.println("source: " + sourceIp + ":" + sourcePort +
                       ", dest: " + destIp + ":" + destPort + ", prot " + protocol);
  }

  private void feedIP4 ( ByteBuffer bodyBuf ) throws UnknownHostException {
    long linkType = get4Long(bodyBuf, 20);
    long length = get4Long(bodyBuf, 24);
    if ( linkType != 1 )
      return;

    int frameType = get2Int(bodyBuf, 40);
    if ( frameType != 2048 )
      return;

    int proto = get1Int(bodyBuf, 42);
    System.out.println("linkType: " + linkType + ", frameType: " + frameType + ", length: " + length +
                       ", proto: " + proto);
  }

  private long get4Long ( ByteBuffer buf, int startPos ) {
    byte[] b = new byte[4];
    buf.position(startPos);
    buf.get(b);
    long l = 0;
    l |= b[0] & 0xFF;
    l <<= 8;
    l |= b[1] & 0xFF;
    l <<= 8;
    l |= b[2] & 0xFF;
    l <<= 8;
    l |= b[3] & 0xFF;
    return l;
  }

  private int get2Int ( ByteBuffer buf, int startPos ) {
    byte[] b = new byte[2];
    buf.position(startPos);
    buf.get(b);
    int i = 0;
    i |= b[0] & 0xFF;
    i <<= 8;
    i |= b[1] & 0xFF;
    return i;
  }

  private int get1Int ( ByteBuffer buf, int startPos ) {
    byte[] b = new byte[1];
    buf.position(startPos);
    buf.get(b);
    int i = 0;
    i |= b[0] & 0xFF;
    return i;
  }

  private String getIp ( ByteBuffer buf, int startPos ) throws UnknownHostException {
    byte[] b = new byte[4];
    buf.position(startPos);
    buf.get(b);

    InetAddress inet = InetAddress.getByAddress(b);
    return inet.toString();
  }   
}
