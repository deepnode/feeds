package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.nio.ByteBuffer;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapAddr;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.packet.Payload;

public class Sniff {

  private BufferedReader inbr = null;
  private Pcap pcap = null;
  private PcapPacket packet = new PcapPacket(JMemory.POINTER);
  private Tcp tcp = new Tcp();
  private Udp udp = new Udp();
  private Icmp icmp = new Icmp();
  private Ip4 ip4 = new Ip4();
  private Ip6 ip6 = new Ip6();
  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private HashMap<String, String> domainMap = new HashMap<String, String>();
  private boolean isWindows = false;
  private SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.S");
  private static String outputAddress;

  public static void main ( String[] args ) {
    try {
      outputAddress = "localhost";
      Sniff sniff = new Sniff();
      int intnum = -1;
      if ( args.length > 0 )
        intnum = Integer.parseInt(args[0]);
      if ( args.length > 1 )
        outputAddress = args[1];
      sniff.setup(intnum, outputAddress);
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  private void monitor () throws IOException {
    boolean isGood = true;
    long lastPing = 0;
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();
      }

      if ( pcap != null ) 
        monitorPcap();
      else {
        try {
          Thread.sleep(250);
        }
	catch ( InterruptedException ie ) {}
      }
    }
  }

  public void setup ( int indexUse, String outputAddress ) {
    String os = System.getProperty("os.name").toLowerCase();
    if ( os.indexOf("win") > -1 )
      isWindows = true;

    List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
    StringBuilder errbuf = new StringBuilder();     // For any error msgs

    int r = Pcap.findAllDevs(alldevs, errbuf);
    if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
      System.err.printf("Can't read list of devices, error is %s\n", 
        errbuf.toString());
      return;
    }

    int i = 0;
    String nameUse = null;
    for ( PcapIf iface : alldevs ) {
      String key = iface.getName();
      if ( key.length() > 10 )
        key = key.substring(0, 10);
      if ( iface.getDescription() != null ) {
        key += ":" + iface.getDescription();
        if ( key.length() > 36 )
          key = key.substring(0, 36);
      }
      List<PcapAddr> addrs = iface.getAddresses();
      if ( addrs != null && addrs.size() > 0 ) {
        key += ":" + addrs.get(0).toString();
        if ( key.length() > 66 )
          key = key.substring(0, 66);
      }

      if ( indexUse == -1 )
        System.out.println(key);
      else if ( i == indexUse ) {
        nameUse = iface.getName();
	break;
      }

      i++;
    }

    if ( nameUse == null )
      return;

    StringBuilder errbuf2 = new StringBuilder();     // For any error msgs
    int snaplen = 1024;           // Capture all packets, no trucation
    int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
    int timeout = 50;           // 10 seconds in millis
    pcap = Pcap.openLive(nameUse, snaplen, flags, timeout, errbuf2);
    if (pcap == null) {
      System.err.printf("Error while opening device for capture: %s\n", 
        errbuf.toString());
      return;
    }

    while ( true ) {
      Socket s = null;
      try {
        s = new Socket(outputAddress, 4021);
        pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("pcap_sniff");
        pw.flush();
        monitor();
      }
      catch ( Exception e ) {
        try {
          pw.close();
        }
        catch ( Exception e2 ) {
        }
        try {
          br.close();
        }
        catch ( Exception e2 ) {
        }
        try {
          if ( s != null )
            s.close();
        }
        catch ( Exception e3 ) {
        }
        System.out.println("error: " + e);
	try {
          Thread.sleep(8000);
	}
	catch ( InterruptedException ie ) {}
      }
    }
  }

  private void monitorPcap () throws IOException {
    int ret = pcap.nextEx(packet);

    if ( ret == 1 ) {
      String destIP = null;
      String sourceIP = null;
      String destProt = "other";
      String sourceProt = "other";
      String srcPort = "";
      String destPort = "";

      if ( packet.hasHeader(ip4) ) {
        destIP = InetAddress.getByAddress(null, ip4.destination()).toString();
        sourceIP = InetAddress.getByAddress(null, ip4.source()).toString();
      }
      else if ( packet.hasHeader(ip6) ) {
        destIP = InetAddress.getByAddress(null, ip6.destination()).toString();
        sourceIP = InetAddress.getByAddress(null, ip6.source()).toString();
      }
      else {
        return;
      }

      if ( packet.hasHeader(tcp) ) {
        //System.out.println("dest: {" + destIP + "}, " + tcp.destination());
        //System.out.println("src: {" + sourceIP + "}, " + tcp.source());
        if ( (destIP.equals("/" + outputAddress) && tcp.destination() == 4021) ||
             (sourceIP.equals("/" + outputAddress) && tcp.source() == 4021) )
          return;

        if ( tcp.destination() < 5024 )
          destPort = String.valueOf(tcp.destination());
	if ( tcp.source() < 5024 )
          srcPort = String.valueOf(tcp.source());
        destProt = "tcp" + destPort;
        sourceProt = "tcp" + srcPort;
      }
      else if ( packet.hasHeader(icmp) ) {
        destProt = "icmp";
        sourceProt = "icmp";
      }
      else if ( packet.hasHeader(udp) ) {
        if ( udp.destination() < 5024 )
          destPort = String.valueOf(udp.destination());
	if ( udp.source() < 5024 )
          srcPort = String.valueOf(udp.source());
        destProt = "udp" + destPort;
        sourceProt = "udp" + srcPort;
      }

      JBuffer buffer = packet.getHeader(new Payload());
      String tag = null;
      try {
        tag = getTag(buffer);
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
      updateIP(destProt, sourceProt, destIP, sourceIP, packet.getTotalSize(), tag);
    }
  }

  private void updateIP ( String destProt, String sourceProt, String destAddr,
                          String sourceAddr, int len, String tag ) {
    if ( destAddr.startsWith("/") )
      destAddr = destAddr.substring(1, destAddr.length());
    if ( sourceAddr.startsWith("/") )
      sourceAddr = sourceAddr.substring(1, sourceAddr.length());

    String destLocation = getLocation(destAddr);
    String sourceLocation = getLocation(sourceAddr);

    StringBuffer sb = new StringBuffer(String.valueOf(System.currentTimeMillis()));
    sb.append('\t');
    sb.append(sourceLocation);
    sb.append('|');
    sb.append(sourceAddr);
    sb.append('|');
    sb.append(sourceProt);
    sb.append('\t');
    sb.append(destLocation);
    sb.append('|');
    sb.append(destAddr);
    sb.append('|');
    sb.append(destProt);
    sb.append('\t');
    sb.append(String.valueOf(len));
    sb.append('|');
    sb.append("0");
    if ( tag != null ) {
      sb.append('\t');
      sb.append(tag);
    }

    String str = sb.toString();
    if ( pw != null ) {
      pw.println(str);
      pw.flush();
    }
  }

  private String getTag ( JBuffer buf ) {
    if ( buf == null )
      return null;

    int harvested = 0;
    StringBuilder res = new StringBuilder();
    for ( int i = 0; i < buf.size(); i++ ) {
      char c = buf.getUTF8Char(i);
      if ( isInRange(c) )
        res.append(c);
      else {
        if ( res.length() >= 3 )
          break;
        res = new StringBuilder();
      }

      if ( res.length() >= 8 || i >= 40 )
        break;
    }

    if ( res.length() < 3 )
      return null;
    return res.toString();
  }

  private boolean isInRange ( char c ) {
    if ( (c >= 0x30 && c <= 0x39) ||
         (c >= 0x41 && c <= 0x5a) ||
         (c >= 0x61 && c <= 0x7a) )
      return true;
    return false;
  }

  private String getLocation ( String addr ) {
    String location = "ext";
    if ( addr.startsWith("192.168") || addr.startsWith("10.") )
      location = "int";
    else if ( addr.startsWith("172.") && addr.charAt(6) == '.' ) {
      try {
        int i = Integer.parseInt(addr.substring(4, 6));
        if ( i >= 16 && i < 32 )
          location = "int";
      }
      catch ( Exception e ) {}
    }
    else if ( addr.toLowerCase().startsWith("fc") || addr.toLowerCase().startsWith("fd") )
      location = "int";

    if ( addr.endsWith(".1") || addr.endsWith(".255") || addr.endsWith(".0") )
      location = "ctrl";

    String domain = "na";
    if ( !addr.equals("na") ) {
      domain = domainMap.get(addr);
      if ( domain == null ) {
        domain = lookupDomain(addr);
        domainMap.put(addr, domain);
      }
    }

    return location + "|" + domain;
  }

  private String lookupDomain ( String addr ) {
    String domain = "unk";
    try {
      String[] cmd = {"nslookup", addr};
      Process p = Runtime.getRuntime().exec(cmd);
      BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
      String line = null;
      int i;
      long start = System.currentTimeMillis();
      int lineIndex = 5;
      if ( isWindows )
        lineIndex = 4;

      for ( i = 0; i < lineIndex; i++ ) {
        while ( (line = br.readLine()) == null && System.currentTimeMillis() < start + 800 )
          Thread.sleep(5);
	if ( line == null )
          break;
        //System.out.println(line);
      }
      p.destroy();

      if ( i == lineIndex ) {
        // winders
        if ( isWindows ) {
          String[] split = line.split("\\.");
          if ( split.length >= 3 )
            domain = split[split.length - 2] + "." + split[split.length - 1];
        }
        else {
          int eqInd = line.indexOf('=');
          if ( eqInd != -1 ) {
            String[] split = line.substring(eqInd + 2, line.length()).split("\\.");
            if ( split.length >= 3 )
              domain = split[split.length - 2] + "." + split[split.length - 1];
          }
        }
      }
    }
    catch ( Exception e ) {
      System.out.println("error getting domain for " + addr + ": " + e);
      e.printStackTrace(System.out);
    }
    return domain;
  }
}


