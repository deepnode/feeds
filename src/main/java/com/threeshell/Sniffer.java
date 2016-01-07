package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.text.ParseException;
import java.nio.ByteBuffer;
import java.util.concurrent.*;
import java.util.zip.DeflaterOutputStream;
import java.security.GeneralSecurityException;

public class Sniffer implements Runnable, MsgSource {

  public static final int STATUS_END = 1;
  public static final int STATUS_CONTINUE = 2;
  public static final int STATUS_RECORD = 3;

  private byte[] packetBuf = new byte[140000];
  private int packetCacheInd = 0;
  private byte[] alertLine = new byte[5000];
  private int alertInd = 0;
  private Pro2be probe;

  boolean debug = false;

  private String dev;
  private String customCommand = null;
  private boolean isCustom = false;
  private boolean isSorted = false;
  private String src1 = null;
  private String src3;
  private String src4;
  private String dst1;
  private String dst3;
  private String dst4;
  private int packetLen;
  private int payloadLen;
  private int hdrLen;
  private StringBuilder tag = null;
  private long ts;
  private long prevTs = -1;
  private String prevHeader = null;

  private String cmd = "";
  private Process p = null;
  private BufferedReader br;
  private BufferedReader errBr;
  private int c;

  private boolean hasMore = true;
  private long curTime;
  private String curMsg;
  private boolean moveForward = false;
  private int readCount = 0;

  public Sniffer ( Pro2be probe, String dev ) {
    this.probe = probe;
    this.dev = dev;
  }

  public Sniffer ( Pro2be probe, String cmd, boolean isCustom, boolean isSorted ) {
    this.probe = probe;
    this.customCommand = cmd;
    this.isCustom = isCustom;
    this.isSorted = isSorted;
  }

  private void execCommand () throws IOException {
    cmd = customCommand;
    if ( !isCustom ) {
      String options = " -tt -n -e";
      if ( probe.snarfPackets )
        options += " -xx -s 65535";
      options += " -i " + dev;

      cmd = "tcpdump" + options;
      if ( probe.isWindows )
        cmd = "windump" + options;
    }

    p = null;
    br = null;
    System.out.println("running {" + cmd + "}");
    p = Runtime.getRuntime().exec(cmd);
    br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    errBr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
    c = -1;
  }

  private void cleanupCommand () {
    try {
      if ( br != null )
        br.close();
      if ( errBr != null )
        errBr.close();
      if ( p != null )
        p.destroy();
      System.out.println("process {" + cmd + "} cleaned up");
    }
    catch ( Exception e ) {
      System.out.println("error cleaning up {" + cmd + "}: " + e);
      e.printStackTrace(System.out);
    }
  }

  private int readChar () throws IOException {
    int status = STATUS_CONTINUE;
    c = br.read();
    if ( c == -1 )
      return STATUS_END;

    if ( c == '\r' || c == '\n' ) {
      if ( alertInd > 0 ) {
        String line = new String(alertLine, 0, alertInd);
        try {
          if ( alertLine[0] == '\t' )
            snarfHex();
          else {
            if ( src1 != null )
              status = sendRecord();
            readHeader(line);
          }
        }
        catch ( Exception e ) {
          System.out.println("error " + e + " on {" + line + "}");
          e.printStackTrace(System.out);
        }

        alertInd = 0;
      }
    }
    else {
      if ( alertInd == alertLine.length )
        System.out.println("OVERLONG {" + new String(alertLine, 0, alertInd) + "}");
      else if ( alertInd < alertLine.length ) {
        alertLine[alertInd] = (byte)c;
        alertInd++;
      }
    }
    return status;
  }

  public void run () {
    while ( !probe.die ) {
      try {
        execCommand();
        while ( !probe.die ) {
          if ( br.ready() ) {
            if ( readChar() == STATUS_END )
              break;
          }
          else if ( errBr.ready() ) {
            c = errBr.read();
          }
          else {
            try {
              Thread.sleep(20);
            }
            catch ( Exception e ) {}
          }
        }
      }
      catch ( Exception e ) {
        System.out.println("sniffer thread error: " + e);
        e.printStackTrace(System.out);
      }
      finally {
        cleanupCommand();
      }
    }
  }

  private void readHeader ( String line ) throws ParseException {
    src1 = "unknown";
    src3 = "unknown";
    src4 = "unknown";
    dst1 = "unknown";
    dst3 = "unknown";
    dst4 = "unknown";
    hdrLen = 0;
    tag = new StringBuilder();
    packetCacheInd = 0;

    try {
      int tsDot = line.indexOf('.');
      ts = Long.parseLong(line.substring(0, tsDot)) * 1000l;
      ts += Long.parseLong(line.substring(tsDot + 1, tsDot + 4));
      //if ( prevTs != -1 && System.currentTimeMillis() - prevTs > 2000 ) {
      //  System.out.println("big ts gap: " + line);
      //  System.out.println("prevHeader: " + prevHeader);
      //}
      //prevTs = System.currentTimeMillis();
      //prevHeader = line;

      int i = line.indexOf(' ', tsDot + 8);
      src1 = line.substring(tsDot + 8, i);
      int i2 = line.indexOf(',', i + 3);
      dst1 = line.substring(i + 3, i2);

      int i3 = line.indexOf(' ', i2 + 2);
      String frameType = line.substring(i2 + 2, i3);
      if ( frameType.charAt(frameType.length() - 1) == ',' )
        frameType = frameType.substring(0, frameType.length() - 1);

      if ( frameType.equals("802.3") ) {
        int lengthInd = line.indexOf("length", i3 + 1);
        int colonInd = line.indexOf(':', lengthInd);
        packetLen = Integer.parseInt(line.substring(lengthInd + 7, colonInd));
        parse802dot3(line, colonInd);
      }
      else {
        int i4 = line.indexOf(' ', i3 + 1);
        String frameProt = line.substring(i3 + 1, i4);
        int lengthInd = line.indexOf("length", i4 + 1);
        int colonInd = line.indexOf(':', lengthInd);
        packetLen = Integer.parseInt(line.substring(lengthInd + 7, colonInd));

        if ( frameProt.equals("IPv4") || frameProt.equals("IPv6") )
          parseIp(line, colonInd);
        else if ( frameProt.equals("ARP") )
          parseArp(line, colonInd);
      }
    }
    catch ( Exception e ) {
      System.out.println("error reading {" + line + "}: " + e);
      e.printStackTrace(System.out);
    }
  }

  private int sendRecord () {
    byte[] buf = null;
    if ( packetCacheInd > 0 ) {
      buf = new byte[packetCacheInd];
      for ( int i = 0; i < packetCacheInd; i++ )
        buf[i] = packetBuf[i];
    }

    String str = getTag(buf);
    if ( str != null )
      addTag(str);

    boolean srcInternal = probe.isInternal(src3);
    boolean dstInternal = probe.isInternal(dst3);

    if ( probe.treeMode == Pro2be.TREEMODE_IP ) {
      addTag("_i_srcMac=" + src1);
      addTag("_i_dstMac=" + dst1);
      if ( srcInternal )
        src1 = "internal";
      else
        src1 = "external";

      if ( dstInternal )
        dst1 = "internal";
      else
        dst1 = "external";
    }

    String src2 = doLoc(src3, srcInternal);
    String dst2 = doLoc(dst3, dstInternal);

    InternalNet srcNet = probe.checkInternalNets(src3);
    if ( srcNet != null ) {
      src1 = srcNet.level1;
      src2 = srcNet.level2;
    }

    InternalNet dstNet = probe.checkInternalNets(dst3);
    if ( dstNet != null ) {
      dst1 = dstNet.level1;
      dst2 = dstNet.level2;
    }

    String tagStr = tag.toString();
    if ( probe.shouldFilter(src1, src2, src3, src4, dst1, dst2, dst3, dst4, tagStr) )
      return STATUS_CONTINUE;

    long id = probe.addToCache(buf, hdrLen, ts);

    if ( !isSorted ) {
      probe.sendMessage(String.valueOf(id), String.valueOf(ts),
                        src1, src2, src3, src4,
                        dst1, dst2, dst3, dst4,
                        (packetLen > 0 ? packetLen : 1), 0f, tagStr);
    }
    else {
      curTime = ts;
      curMsg = probe.constructMessage(String.valueOf(id), String.valueOf(ts),
                                      src1, src2, src3, src4,
                                      dst1, dst2, dst3, dst4,
                                      (packetLen > 0 ? packetLen : 1), 0f, tagStr);
    }

    probe.attribNode(src3);
    probe.attribNode(dst3);
    return STATUS_RECORD;
  }

  private String doLoc ( String addr, boolean isAddrInternal ) {
    if ( addr.equals("unknown") )
      return "n/a";

    if ( !isAddrInternal )
      return probe.getLocation(addr);

    return "internal";
  }

  private void addTag ( String str ) {
    if ( tag.length() > 0 )
      tag.append(',');
    tag.append(str);
  }

  private void parseIp ( String line, int colonInd ) {
    int i = line.indexOf(' ', colonInd + 2);
    String srcIpPort = line.substring(colonInd + 2, i);

    if ( srcIpPort.equals("truncated-ip6") ) {
      src3 = "error";
      src4 = "truncated-ip6";
      dst3 = "error";
      dst4 = "truncated-ip6";
      addTag("_i_details=" + line.substring(colonInd + 2, line.length()).replace(',', ';'));
      return;
    }
    else if ( srcIpPort.equals("IP6") ) {
      src3 = "error";
      src4 = "ip6";
      dst3 = "error";
      dst4 = "ip6";
      addTag("_i_details=" + line.substring(colonInd + 2, line.length()).replace(',', ';'));
      return;
    }  

    int i2 = line.indexOf(' ', i + 3);
    String dstIpPort = line.substring(i + 3, i2 - 1);

    int detailInd = line.length();
    int i3 = line.indexOf(' ', i2 + 1);

    String protRaw = "unknown";
    if ( i3 > 0 ) {
      protRaw = line.substring(i2 + 1, i3).toLowerCase();
      if ( protRaw.endsWith(",") )
        protRaw = protRaw.substring(0, protRaw.length() - 1);
    }

    String prot = protRaw;
    int lengthInd = line.indexOf("length ", i3);
    if ( lengthInd > -1 ) {
      detailInd = lengthInd - 2;
      int lenSpaceInd = line.indexOf(' ', lengthInd + 7);
      if ( lenSpaceInd < 0 )
        lenSpaceInd = line.length();
      else
        detailInd = line.length();
      try {
        hdrLen = packetLen - Integer.parseInt(line.substring(lengthInd + 7, lenSpaceInd));
      }
      catch ( Exception e ) {
        System.out.println("error parsing {" + line + "}: " + e);
      }
    }

    if ( prot.equals("udp") )
      detailInd = -1;
    else if ( prot.equals("icmp") ||
              prot.equals("icmp6") ||
              prot.equals("igmp") ||
              prot.equals("hbh") ||
              prot.equals("dhcp6") ||
              prot.equals("bootp/dhcp") ||
              prot.equals("ip-proto-64") )
      detailInd = detailInd;
    else if ( prot.length() < 1 ||
              line.indexOf("omain", i2 + 1) > -1 ||
              line.indexOf("unknown.", i2 + 1) > -1 )
      prot = "udp";
    else {
      //if ( prot.length() >= 3 ) {
      //  System.out.println(line);
      //  System.out.println("defaulting {" + prot + "} to tcp");
      //}
      prot = "tcp";
    }

    extractPort(srcIpPort, false, prot);
    extractPort(dstIpPort, true, prot);

    if ( detailInd != -1 ) {
      int detailStartInd = i2 + 1;
      if ( line.charAt(detailStartInd) == ' ' )
        detailStartInd++;
      addTag("_i_details=" + line.substring(detailStartInd, detailInd).replace(',', ';'));
    }	
    probe.macCache.put(src3 + "|" + dst3, new MacPair(src1, dst1));
  }

  private void extractPort ( String ipPort, boolean isDst, String prot ) {
    int dotCount = 0;
    int index = 0;
    int prevIndex = 0;
    while ( index != -1 ) {
      prevIndex = index;
      index = ipPort.indexOf('.', index + 1);
      if ( index != -1 )
        dotCount++;
    }

    if ( dotCount == 4 || dotCount == 1 ) {
      int port = Integer.parseInt(ipPort.substring(prevIndex + 1, ipPort.length()));
      String ip = ipPort.substring(0, prevIndex);
      if ( isDst ) {
        dst3 = ip;
        dst4 = Pro2be.buildProtPort(prot, port);
        addTag("_i_dstPort=" + port);
      }
      else {
        src3 = ip;
        src4 = Pro2be.buildProtPort(prot, port);
        addTag("_i_srcPort=" + port);
      }
    }
    else {
      if ( isDst ) {
        dst3 = ipPort;
        dst4 = prot;
      }
      else {
        src3 = ipPort;
        src4 = prot;
      }
    }
  }

  private void parseArp ( String line, int colonInd ) {
    src4 = "arp";
    dst4 = "arp";
    String arpDetails = line.substring(colonInd + 6, line.length());
    addTag("_i_details=" + arpDetails.replace(',', ';')); 
    if ( arpDetails.startsWith("who-has") ) {
      int i = arpDetails.indexOf(' ', 8);
      dst3 = arpDetails.substring(8, i);
      int j = arpDetails.indexOf("tell", i);
      src3 = arpDetails.substring(j + 5, arpDetails.length());
    }
    else if ( arpDetails.startsWith("reply") ) {
      int i = arpDetails.indexOf(' ', 6);
      src3 = arpDetails.substring(6, i);
    }
  }

  private void parse802dot3 ( String line, int colonInd ) {
    src4 = "802.3";
    dst4 = "802.3";
    String details = line.substring(colonInd + 2, line.length());
    addTag("_i_details=" + details.replace(',', ';'));
  }

  private void snarfHex () {
    if ( debug )
      System.out.println(new String(alertLine, 0, alertInd));
    boolean colonReceived = false;
    char store = '.';
    for ( int i = 0; i < alertInd; i++ ) {
      char c = (char)alertLine[i];
      if ( c == ':' )
        colonReceived = true;

      if ( !colonReceived || (!(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f')) )
        continue;

      if ( store != '.' ) {
        addByte(store, c);
        store = '.';
      }
      else
        store = c;
    }
    if ( debug )
      System.out.println();
  }

  private void addByte ( char highC, char lowC ) {
    int intByte = convertHexChar(highC) * 16 + convertHexChar(lowC);
    if ( debug )
      System.out.print(String.valueOf(intByte) + " ");

    if ( intByte >= 128 )
      intByte = (128 - (intByte - 128)) * -1;
    packetBuf[packetCacheInd] = (byte)intByte; 
    packetCacheInd++;
  }

  private int convertHexChar ( char c ) {
    if ( c >= '0' && c <= '9' )
      return c - '0';
    if ( c >= 'a' && c <= 'f' )
      return 10 + (c - 'a');
    return 0;
  }

  private String getTag ( byte[] buf ) {
    if ( buf == null || buf.length < 40 )
      return null;

    int harvested = 0;
    StringBuilder res = new StringBuilder();
    for ( int i = 30; i < buf.length; i++ ) {
      char c = (char)buf[i];
      if ( Pro2be.isInRange(c) ) {
        res.append(c);
        if ( debug )
          System.out.print(c);
      }
      else {
        if ( res.length() >= 4 )
          break;
        res = new StringBuilder();
      }

      if ( res.length() >= 10 || i >= 120 )
        break;
    }

    if ( res.length() < 4 )
      return null;
    return res.toString();
  }

  public boolean hasMore () {
    if ( !hasMore )
      return false;

    if ( p != null && !moveForward )
      return true;

    try {
      if ( p == null )
        execCommand();

      int status = STATUS_CONTINUE;
      while ( status == STATUS_CONTINUE )
        status = readChar();

      if ( status == STATUS_END ) {
        cleanupCommand();
        hasMore = false;
        return false;
      }

      return true;
    }
    catch ( Exception e ) {
      hasMore = false;
      System.out.println("command {" + cmd + "} failure: " + e);
      e.printStackTrace(System.out);
      cleanupCommand();
      return false;
    }
  }

  public long getCurTime () {
    return curTime;
  }

  public String getCurMsg () {
    moveForward = true;
    //readCount++;
    //if ( readCount % 1000 == 0 )
    //  System.out.println("source " + cmd + " readCount " + readCount);
    return curMsg;
  }
}
