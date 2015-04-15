package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.nio.ByteBuffer;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapDumper;
import org.jnetpcap.PcapHandler;
import org.jnetpcap.PcapIf;
import org.jnetpcap.protocol.network.*;
import org.jnetpcap.protocol.tcpip.*;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.PcapPacket;

public class Probe {

  public static final int MODE_PCAP = 1;
  public static final int MODE_BARNYARD2 = 2;

  private int mode = MODE_PCAP;
  private BufferedReader inbr = null;

  Pcap pcap = null;
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
  private ArrayList<TSSubnet> subnets = new ArrayList<TSSubnet>();
  private boolean isWindows = false;
  private PrintWriter filePw = null;
  private SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.S");
  private boolean dumpScreen = false;

  public static void main ( String[] args ) {
    try {
      Probe sniff = new Probe(args[0]);
      if ( args.length > 1 ) {
        if ( args[1].equalsIgnoreCase("screen") ) {
          sniff.setScreen();
          if ( args.length > 2 )
            sniff.setOutputFile(args[2]);
        }
        else
          sniff.setOutputFile(args[1]);
      }
      sniff.go();
    }
    catch ( Exception e ) {
      System.out.println("error: " + e);
      e.printStackTrace(System.out);
    }
  }

  public Probe ( String intSub ) throws java.io.IOException {
    if ( intSub.equals("barnyard2") ) {
      mode = MODE_BARNYARD2;
      inbr = new BufferedReader(new InputStreamReader(System.in));
      System.out.println("Listening for snort alerts...");
    }
    else {
      mode = MODE_PCAP;
      List<PcapIf> alldevs = new ArrayList<PcapIf>(); // Will be filled with NICs
      StringBuilder errbuf = new StringBuilder();     // For any error msgs

      int r = Pcap.findAllDevs(alldevs, errbuf);
      if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
        System.err.printf("Can't read list of devices, error is %s\n", 
          errbuf.toString());
        return;
      }
      PcapIf device = alldevs.get(1); // We know we have atleast 1 device

      int snaplen = 64 * 1024;           // Capture all packets, no trucation
      int flags = Pcap.MODE_PROMISCUOUS; // capture all packets
      int timeout = 10 * 1000;           // 10 seconds in millis
      pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);
      if (pcap == null) {
        System.err.printf("Error while opening device for capture: %s\n", 
          errbuf.toString());
        return;
      }
    }
  }

  public void setOutputFile ( String name ) throws IOException {
    filePw = new PrintWriter(new FileWriter(name));
    Runtime.getRuntime().addShutdownHook(new RunWhenShuttingDown(this));
  }

  public void setScreen () {
    dumpScreen = true;
  }

  public void closeFile () {
    try {
      filePw.close();
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  public void go () throws UnknownHostException, IOException, SecurityException,
                           InterruptedException {
    BufferedReader configBr = new BufferedReader(new FileReader("sniff_config.txt"));
    String os = configBr.readLine();
    if ( os.equalsIgnoreCase("windows") )
      isWindows = true;
    String vizHost = configBr.readLine();
    String line;
    while ( (line = configBr.readLine()) != null )
      subnets.add(new TSSubnet(line));
    configBr.close();

    while ( true ) {
      Socket s = null;
      try {
        if ( !dumpScreen ) {
          s = new Socket(vizHost, 4020);
          pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
          br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        }
        else
          pw = new PrintWriter(new OutputStreamWriter(System.out));
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
        Thread.sleep(10000);
      }
    }
  }

  private void monitor () throws IOException {
    boolean isGood = true;
    long lastPing = 0;
    while ( pw != null && isGood ) {
      if ( !dumpScreen && 
           (lastPing == 0 || System.currentTimeMillis() - lastPing > 5000) ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();
      }
 
      if ( mode == MODE_PCAP )
        monitorPcap();
      else if ( mode == MODE_BARNYARD2 )
        monitorBarnyard2();
    }
  }

  private void monitorBarnyard2 () throws IOException {
    String line = inbr.readLine();

    if ( line != null ) {
      String[] split = line.split("\t");
      String alert = split[7].trim().replace('|', '_');
      snortIP(alert, split[2], split[3], split[1], split[6], split[5]);
    }
  }

  private void snortIP ( String destProt, String sourceProt, String destAddr, String sourceAddr, String len, String pri ) {
    String destLocation = getLocation(destAddr);
    String sourceLocation = getLocation(sourceAddr);

    StringBuffer sb = new StringBuffer(sourceLocation);
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
    sb.append(len);
    sb.append('|');

    float fpri = 0f;
    float snortPri = Float.parseFloat(pri);
    if ( snortPri > 0f )
      fpri = 1f / snortPri;
    sb.append(String.valueOf(fpri));

    String str = sb.toString();
    pw.println(str);
    pw.flush();
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
        destPort = String.valueOf(tcp.destination());
        srcPort = String.valueOf(tcp.source());
        destProt = "tcp" + destPort;
        sourceProt = "tcp" + srcPort;
      }
      else if ( packet.hasHeader(icmp) ) {
        destProt = "icmp";
        sourceProt = "icmp";
      }
      else if ( packet.hasHeader(udp) ) {
        destPort = String.valueOf(udp.destination());
        srcPort = String.valueOf(udp.source());
        destProt = "udp" + destPort;
        sourceProt = "udp" + srcPort;
      }

      updateIP(destProt, sourceProt, destIP, sourceIP, packet.getTotalSize());
    }
  }

  private void updateIP ( String destProt, String sourceProt, String destAddr, String sourceAddr, int len ) {
    // <categry>|<subcat>|<subcat>\t<category>|<subcat>\t<meas_name>|<meas_value>|<meas_name>|<meas_value>
    if ( destAddr.startsWith("/") )
      destAddr = destAddr.substring(1, destAddr.length());
    if ( sourceAddr.startsWith("/") )
      sourceAddr = sourceAddr.substring(1, sourceAddr.length());

    String destLocation = getLocation(destAddr);
    String sourceLocation = getLocation(sourceAddr);

    StringBuffer sb = new StringBuffer(sourceLocation);
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

    String str = sb.toString();
    if ( pw != null ) {
      pw.println(str);
      pw.flush();
    }

    if ( filePw != null )
      filePw.println(sdf.format(new Date()) + "\t" + str);

    //System.out.println("sent <" + addr + ", " + len + ">");
  }

  private String getLocation ( String addr ) {
    for ( TSSubnet sub : subnets ) {
      if ( addr.startsWith(sub.subnetPiece) )
        return sub.msgPiece;
    }

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

  class TSSubnet {

    public String msgPiece;
    public String subnetPiece;

    public TSSubnet ( String line ) {
      String[] split = line.split("\t");
      subnetPiece = split[0];
      msgPiece = split[1];
    }
  }

  class RunWhenShuttingDown extends Thread {

    private Probe sniff;

    public RunWhenShuttingDown ( Probe sniff ) {
      this.sniff = sniff;
    }

    public void run () {
      System.out.println("sniffer closing dump file, shutting down");
      sniff.closeFile();
    }
  }
}


