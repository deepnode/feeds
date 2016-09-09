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
import org.apache.commons.codec.binary.Base64;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JButton;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class Pro2be implements Runnable {

  public static Pro2be thePro2be = null;
  private BufferedReader inbr = null;
  private int nextInd = 0;
  private int nextNMAPId = 1;
  private PrintWriter pw;
  private BufferedReader br;
  private Hashtable<String, String> domainMap = new Hashtable<String, String>();
  private Hashtable<String, NodeAttrs> nodeAttrs = new Hashtable<String, NodeAttrs>();
  public boolean isWindows = false;
  private String domainFname = "pro2be_domains.txt";
  private String filterFname = "pro2be_filters.txt";

  public String addrStr = "localhost";
  public String portStr = "4021";
  public String snortStr = " -K none -i 3 -d -A console";
  public String tcpdumpStr = "dump -tt -n -e -xx -s 65535 -r yourpcap.pcap";
  public static String loadCommand = "dump -tt -n -e -xx -s 65535 -r ";

  private long nextMsgId = 1l;
  private TreeMap<Long, PacketHolder> packetCache = new TreeMap<Long, PacketHolder>();
  private long totalPacketBytes = 0l;
  public String overrideDir;
  public String configFname;
  public String storagePath = null;
  public long minFreeSpace = 250000000;

  public InternalNet[] internalNets = null;
  public ClientNet[] clientNets = null;
  public HashSet<String> localIps = null;
  public String[] probeTrackLevels = null;

  public LinkedBlockingQueue<String> outQueue = new LinkedBlockingQueue<String>(8000);
  public LinkedBlockingQueue<String> nodeAttrQueue = new LinkedBlockingQueue<String>(1000);
  public LinkedList<FeedSender> feedSenders = new LinkedList<FeedSender>();
  public Hashtable<String, MacPair> macCache = new Hashtable<String, MacPair>();
  private ProbeFilter[] filters = null;
  private ProbeFilter[] flags = null;

  private Snorter snort = null;
  private Thread snortThread = null;
  public int ATTRLOOKUP_THREAD_COUNT = 4;
  private AttrLookup[] attrLookups = null;
  private Thread[] attrLookupThreads = null;
  private Thread mft = null;

  public boolean doCountry = false;
  public boolean snarfPackets = true;
  public boolean makeInternalCritical = true;
  public boolean noResolve = false;

  public static final String[] TREEMODELABELS = {"mac", "ip"};
  public static final int TREEMODE_MAC = 0;
  public static final int TREEMODE_IP = 1;
  public int treeMode = TREEMODE_IP;
  public static boolean fillLowers = false;

  private byte[] countryBuf = new byte[1000];
  public static boolean useGui = true;
  public static boolean connected = false;
  public static int max_packet_bytes = 20000000;
  private static Pro2beFrame frame;
  public boolean die = false;
  private int listenPort = 4020;
  private boolean monStarted = false;
  public Collector collector;
  
  public static void main ( String[] args ) {
    Pro2be sniff = new Pro2be();
    thePro2be = sniff;
    try {
      sniff.setup();
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
      System.exit(2);
    }

    if ( args.length > 0 && args[0].equals("nogui") ) {
      try {
        sniff.useGui = false;
        sniff.setupSniff();
        sniff.run();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
    else if ( args.length > 0 && args[0].equals("daemon") ) {
      try {
        sniff.useGui = false;
        sniff.setupSniff();
        sniff.daemon();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
    else if ( args.length > 0 && args[0].equals("collect") ) {
      try {
        sniff.useGui = false;
        sniff.connected = true;
        sniff.setupSniff();
        sniff.startCollecting();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
    else {
      EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            frame = new Pro2beFrame();
            frame.setVisible(true);
            frame.setup();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
      });
    }
  }

  public Pro2be () {
  }

  public static void createIfNotExist ( String dirName ) throws IOException {
    File dir = new File(dirName);
    if ( !dir.exists() ) {
      System.out.println("creating directory " + dirName);
      dir.mkdir();
    }
  }

  private void readConfigFile ( Reader r ) throws IOException {
    Properties props = new Properties();
    props.load(r);
    r.close();
    addrStr = props.getProperty("consoleaddr");
    snortStr = props.getProperty("snortcommand");
    portStr = props.getProperty("consoleport");
    String maxPackStr = props.getProperty("max_packet_bytes");
    if ( maxPackStr != null ) {
      max_packet_bytes = Integer.parseInt(maxPackStr);
      System.out.println("max packet bytes set to " + max_packet_bytes);
    }
    String strListen = props.getProperty("listenport");
    if ( strListen != null )
      listenPort = Integer.parseInt(strListen);

    doCountry = readBooleanProp(props, "docountry", doCountry);
    snarfPackets = readBooleanProp(props, "snarfpackets", snarfPackets);
    makeInternalCritical = readBooleanProp(props, "makeinternalcritical", makeInternalCritical);
    fillLowers = readBooleanProp(props, "filllowers", fillLowers);
    noResolve = readBooleanProp(props, "noresolve", noResolve);

    String strTreeMode = props.getProperty("treemode");
    if ( strTreeMode != null && strTreeMode.equals("ip") )
      treeMode = TREEMODE_IP;

    storagePath = props.getProperty("storagepath");
    String strMinFree = props.getProperty("minfreespace");
    if ( strMinFree != null )
      minFreeSpace = Long.parseLong(strMinFree);
  }

  public static boolean readBooleanProp ( Properties props, String name, boolean curVal ) {
    String strProp = props.getProperty(name);
    if ( strProp != null )
      return Boolean.parseBoolean(strProp);
    return curVal;
  }

  private void writeConfigFile () throws IOException {
    PrintWriter pw = new PrintWriter(new FileWriter(overrideDir + configFname));
    pw.println("consoleaddr=" + addrStr);
    pw.println("consoleport=" + portStr);
    pw.println("listenport=" + String.valueOf(listenPort));
    pw.println("docountry=" + String.valueOf(doCountry));
    pw.println("noresolve=" + String.valueOf(noResolve));
    pw.println("snarfpackets=" + String.valueOf(snarfPackets));
    pw.println("makeinternalcritical=" + String.valueOf(makeInternalCritical));
    pw.println("filllowers=" + String.valueOf(fillLowers));
    pw.println("snortcommand=" + snortStr.replace("\\", "\\\\"));
    pw.println("max_packet_bytes=" + max_packet_bytes);
    pw.println("treemode=" + TREEMODELABELS[treeMode]);
    if ( storagePath != null )
      pw.println("storagepath=" + storagePath.replace("\\", "\\\\"));
    pw.println("minfreespace=" + minFreeSpace);
    pw.close();
  }

  public void setup () throws IOException, FileNotFoundException {
    String os = System.getProperty("os.name").toLowerCase();
    if ( os.indexOf("win") > -1 )
      isWindows = true;

    if ( isWindows ) {
      tcpdumpStr = "win" + tcpdumpStr;
      snortStr = "c:\\snort\\bin\\snort -c c:\\snort\\etc\\snort.conf" + snortStr;
    }
    else {
      tcpdumpStr = "tcp" + tcpdumpStr;
      snortStr = "snort -c /etc/snort/snort.conf" + snortStr;
    }
      
    overrideDir = System.getProperty("user.home") + File.separator + ".deepnode";
    createIfNotExist(overrideDir);
    overrideDir += File.separator;
    configFname = "pro2be.properties";
    File configf = new File(overrideDir + configFname);
    if ( configf.exists() ) {
      readConfigFile(new FileReader(overrideDir + configFname));
      if ( treeMode == TREEMODE_IP ) {
        readInternalNets();
        readClientNets();
      }
    }
    else
      System.out.println("no config found at " + overrideDir + configFname + ", using defaults");

    File domainf = new File(overrideDir + domainFname);
    if ( domainf.exists() )
      readDomains(new FileReader(overrideDir + domainFname));

    File filterf = new File(overrideDir + filterFname);
    if ( filterf.exists() )
      readFilters(new FileReader(overrideDir + filterFname));
  }

  private void readDomains ( Reader r ) throws IOException {
    BufferedReader br = new BufferedReader(r);
    String line;
    while ( (line = br.readLine()) != null ) {
      String[] split = line.split("\\t");
      domainMap.put(split[0], split[1]);
    }
    br.close();
    System.out.println("loaded " + domainMap.size() + " domain entries");
  }

  private void readFilters ( Reader r ) throws IOException {
    BufferedReader br = new BufferedReader(r);
    String line;
    LinkedList<String> lines = new LinkedList<String>();
    while ( (line = br.readLine()) != null )
      lines.add(line);
    br.close();

    String[] filtArray = new String[lines.size()];
    int i = 0;
    for ( String str : lines ) {
      filtArray[i] = str;
      i++;
    }

    loadFilters(filtArray);
  }

  private void loadFilters ( String[] filtArray ) {
    LinkedList<ProbeFilter> filterList = new LinkedList<ProbeFilter>();
    LinkedList<ProbeFilter> flagList = new LinkedList<ProbeFilter>();
    for ( String line : filtArray ) {
      try {
        ProbeFilter pf = new ProbeFilter(line);
        if ( pf.isFlag )
          flagList.add(pf);
        else
          filterList.add(pf);
      }
      catch ( Exception e ) {
        System.out.println("exception adding filter {" + line + "}: " + e);
        e.printStackTrace(System.out);
      }
    }

    int filterCount = 0;
    if ( flagList.size() > 0 ) {
      flags = new ProbeFilter[flagList.size()];
      int i = 0;
      for ( ProbeFilter pf : flagList ) {
        flags[i] = pf;
        i++;
      }
      filterCount += flagList.size();
    }

    if ( filterList.size() > 0 ) {
      filters = new ProbeFilter[filterList.size()];
      int i = 0;
      for ( ProbeFilter pf : filterList ) {
        filters[i] = pf;
        i++;
      }
      filterCount += filterList.size();
    }
    System.out.println("loaded " + filterCount + " filters");
  }

  public void writeDomains () throws IOException {
    PrintWriter pw = new PrintWriter(new FileWriter(overrideDir + domainFname));
    for ( Map.Entry<String, String> entry : domainMap.entrySet() )
      pw.println(entry.getKey() + '\t' + entry.getValue());
    pw.close();
    System.out.println("wrote out " + domainMap.size() + " domain entries");
  }

  public void readInternalNets () throws IOException, FileNotFoundException {
    String fname = overrideDir + "internal_nets.txt";
    File netF = new File(fname);
    if ( !netF.exists() )
      return;

    LinkedList<InternalNet> ll = new LinkedList<InternalNet>();
    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line;
    while ( (line = br.readLine()) != null ) {
      String[] split = line.split(",");
      if ( split.length != 4 )
        continue;
      ll.add(new InternalNet(split[0], split[1], split[2], split[3]));
    }
    br.close();

    internalNets = new InternalNet[ll.size()];
    int i = 0;
    for ( InternalNet in : ll ) {
      internalNets[i] = in;
      i++;
    }
  }

  public void readClientNets () throws IOException, FileNotFoundException {
    String fname = overrideDir + "client_nets.txt";
    File netF = new File(fname);
    if ( !netF.exists() )
      return;

    LinkedList<ClientNet> ll = new LinkedList<ClientNet>();
    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line = br.readLine();
    String[] levels = line.split("|");
    if ( levels.length != 4 ) {
      System.out.println("client_nets.txt first line {" + line + "} is not four levels");
      System.out.println("example: bobco|corporate|192.168.7.77|probe");
      System.exit(7);
    }
    probeTrackLevels = levels;

    while ( (line = br.readLine()) != null ) {
      String[] split = line.split(",");
      if ( split.length != 5 )
        continue;
      ll.add(new ClientNet(split[0], split[1], split[2], split[3], split[4]));
    }
    br.close();

    clientNets = new ClientNet[ll.size()];
    int i = 0;
    for ( ClientNet in : ll ) {
      clientNets[i] = in;
      i++;
    }
  }

  public ClientNet checkClientNets ( String strIP ) {
    if ( clientNets == null || clientNets.length < 1 )
      return null;

    int addr = IPUtils.getNumericIP(strIP);
    for ( ClientNet in : clientNets ) {
      if ( IPUtils.isInSubnet(addr, in.subnet, in.mask) )
        return in;
    }
    return null;
  }

  public InternalNet checkInternalNets ( String strIP ) {
    if ( clientNets != null || internalNets == null || internalNets.length < 1 )
      return null;

    int addr = IPUtils.getNumericIP(strIP);
    for ( InternalNet in : internalNets ) {
      if ( IPUtils.isInSubnet(addr, in.subnet, in.mask) )
        return in;
    }
    return null;
  }

  public void startMon () throws IOException {
    if ( monStarted )
      return;
    monStarted = true;

    if ( useGui ) {
      writeConfigFile();
      Thread t = new Thread(this);
      t.start();
    }

    attrLookups = new AttrLookup[ATTRLOOKUP_THREAD_COUNT];
    attrLookupThreads = new Thread[ATTRLOOKUP_THREAD_COUNT];
    for ( int i = 0; i < ATTRLOOKUP_THREAD_COUNT; i++ ) {
      attrLookups[i] = new AttrLookup(this);
      attrLookupThreads[i] = new Thread(attrLookups[i]);
      attrLookupThreads[i].start();
    }
  }

  public void terminate () {
    die = true;
  }

  public void cleanupSniffs () {
    die = true;
    try {
      Thread.sleep(2000);
    }
    catch ( InterruptedException ie ) {
      System.out.println("interrupted killing processes: " + ie);
    }
    if ( useGui ) {
      frame.statusLabel.setText("Sniffing stopped.");
      frame.monitorButt.setText("SNIFF ALL");
    }
  }

  public void setupSniff () throws IOException {
    LinkedList<String> allDevs = getDevList();
    if ( allDevs == null || allDevs.size() < 1 ) {
      System.out.println("cannot find devices to sniff");
      return;
    }

    die = false;
    startMon();
    if ( useGui )
      frame.monitorButt.setText("STOP");

    loadLocalAddrs();

    for ( String str : allDevs ) {
      Sniffer sniff = new Sniffer(this, str);
      Thread sniffThread = new Thread(sniff);
      sniffThread.start();
    }

    String snortCommand = snortStr;
    if ( snortCommand != null && snortCommand.length() > 0 ) {
      snort = new Snorter(this);
      snortThread = new Thread(snort);
      snortThread.start();
    }

    if ( useGui )
      frame.statusLabel.setText("Sniffing");
    else
      System.out.println("sniffing has begun");
  }

  public LinkedList<String> getDevList () throws IOException {
    String cmd = "tcpdump -D";
    if ( isWindows )
      cmd = "windump -D";
    Process p;
    try {
      p = Runtime.getRuntime().exec(cmd);
    }
    catch ( Exception e ) {
      System.out.println("error running command {" + cmd + "}: " + e);
      if ( useGui )
        frame.statusLabel.setText("command \"" + cmd + "\" fails: " + e);
      return null;
    }

    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    LinkedList<String> allDevs = new LinkedList<String>();
    String line;
    while ( (line = br.readLine()) != null ) {
      int i = line.indexOf(".");
      if ( i > -1 ) {
        String intNum = line.substring(0, i);
        String dev = line.substring(i + 1, line.length());
        if ( dev.startsWith("any ") || dev.equals("lo") )
          System.out.println("ignoring " + line);
        else
          allDevs.add(intNum);
      }
    }
    br.close();
    p.destroy();
    return allDevs;
  }

  private void loadLocalAddrs () throws IOException {
    String cmd = "ifconfig";
    if ( isWindows )
      cmd = "ipconfig";
    Process p;
    try {
      p = Runtime.getRuntime().exec(cmd);
    }
    catch ( Exception e ) {
      System.out.println("error running command {" + cmd + "}: " + e);
      return;
    }

    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    localIps = new HashSet<String>();
    String line;
    while ( (line = br.readLine()) != null ) {
      if ( isWindows ) {
        if ( !line.contains("IPv6 Address") && !line.contains("IPv4 Address") )
          continue;
      }
      else {
        if ( !line.contains("inet addr") && !line.contains("inet6 addr") )
          continue;
      }

      int i = line.indexOf(":");
      if ( i > -1 ) {
        String ip = null;
        if ( isWindows ) {
          ip = line.substring(i + 2, line.length()).toUpperCase();
          int j = ip.indexOf('%');
          if ( j > 0 )
            ip = ip.substring(0, j);
        }
        else {
          if ( line.contains("inet addr") ) {
            int j = line.indexOf(' ', i + 2);
            ip = line.substring(i + 1, j);
          }
          else {
            int j = line.indexOf('/', i + 3);
            ip = line.substring(i + 2, j);
          }
        }

        System.out.println("adding {" + ip + "} to local address set");
        localIps.add(ip);
      }
    }
    br.close();
    p.destroy();
  }

  public void tcpdump ( boolean doIngest ) throws IOException {
    startMon();
    if ( doIngest )
      outQueue.offer("__cg_ingest");

    Sniffer sniff = new Sniffer(this, tcpdumpStr, true, false);
    Thread sniffThread = new Thread(sniff);
    sniffThread.start();
  }

  public void loadPcap ( File[] files ) throws IOException {
    startMon();
    if ( files.length == 1 ) {
      Sniffer sniff = new Sniffer(this, makeLoadCommand(files[0]), true, false);
      Thread sniffThread = new Thread(sniff);
      sniffThread.start();
    }
    else {
      Sniffer[] sniffers = new Sniffer[files.length];
      for ( int i = 0; i < sniffers.length; i++ )
        sniffers[i] = new Sniffer(this, makeLoadCommand(files[i]), true, true);
      Sorter sorter = new Sorter(sniffers, this);
      Thread sortThread = new Thread(sorter);
      sortThread.start();
    }
  }

  private String makeLoadCommand ( File f ) {
    String cmd = "tcp";
    if ( isWindows )
      cmd = "win";

    cmd += loadCommand;
    cmd += f.getAbsolutePath();
    return cmd;
  }

  public static boolean isInRange ( char c ) {
    if ( (c >= 0x30 && c <= 0x39) ||
         (c >= 0x41 && c <= 0x5a) ||
         (c >= 0x61 && c <= 0x7a) )
      return true;
    return false;
  }

  private void sendNodeAttrs ( PrintWriter pw ) {
    for ( Map.Entry<String, NodeAttrs> entry : nodeAttrs.entrySet() ) {
      NodeAttrs na = entry.getValue();
      String addr = entry.getKey();
      for ( Map.Entry<String, String> attrEntry : na.attrs.entrySet() ) {
        String split[] = attrEntry.getKey().split("-");
        pw.println(buildNALine(addr, split[1], attrEntry.getValue(), split[0]));
      }
    }
  }

  public static String buildNALine ( String addr, String name, String value, String type ) {
    String msg = "__na_3\t" + addr + "\t" + name + "\t" + value + "\t" + type;
    return msg;
  }

  public void loadFile ( String fname ) throws UnknownHostException, IOException, SecurityException,
                           ParseException, InterruptedException {
    int port = Integer.parseInt(portStr);
    Socket sload = new Socket(addrStr, port);
    PrintWriter loadpw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(sload.getOutputStream(), true)));
    loadpw.println("playback");
    loadpw.flush();
    loadpw.println("__cg_ingest");
    loadpw.flush();

    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line = null;
    while ( (line = br.readLine()) != null ) {
      loadpw.println(line);
    }

    loadpw.close();
    sload.close();
    br.close();
  }

  public void loadSyslog ( String fname ) throws UnknownHostException, IOException, SecurityException,
                           ParseException, InterruptedException {
    int port = Integer.parseInt(portStr);
    Socket sload = new Socket(addrStr, port);
    PrintWriter loadpw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(sload.getOutputStream(), true)));
    loadpw.println("syslog");
    loadpw.flush();
    loadpw.println("__cg_ingest");
    loadpw.flush();

    SimpleDateFormat ydf = new SimpleDateFormat("yyyy");
    String year = ydf.format(new java.util.Date());
    SimpleDateFormat slsdf = new SimpleDateFormat("yyyy MMM dd HH:mm:ss");
    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line = null;
    int nextMsgId = 1;
    while ( (line = br.readLine()) != null ) {
      String str = parseSyslog(slsdf, line, nextMsgId, year);
      nextMsgId++;
      if ( str != null )
        loadpw.println(str);
    }

    loadpw.close();
    sload.close();
    br.close();
  }

  public void loadOssim ( String fname ) throws UnknownHostException, IOException, SecurityException,
                           ParseException, InterruptedException {
    int port = Integer.parseInt(portStr);
    Socket sload = new Socket(addrStr, port);
    PrintWriter loadpw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(sload.getOutputStream(), true)));
    loadpw.println("ossim");
    loadpw.flush();
    loadpw.println("__cg_ingest");
    loadpw.flush();

    BufferedReader br = new BufferedReader(new FileReader(fname));
    String line = null;
    int nextMsgId = 1;
    while ( (line = br.readLine()) != null ) {
      String ts = getOssimValue(line, "date");
      if ( ts == null )
        continue;

      String srcIp = getOssimValue(line, "src_ip");
      String dstIp = getOssimValue(line, "dst_ip");
      String srcPort = getOssimValue(line, "src_port");
      String dstPort = getOssimValue(line, "dst_port");
      String data = getOssimValue(line, "data");

      String srcp1 = "internal";
      String srcp2 = "internal";
      if ( srcIp == null ) {
        srcIp = "unknown";
        srcp1 = "unknown";
        srcp2 = "unknown";
      }
      else if ( !isInternal(srcIp) ) {
        srcp1 = "external";
        srcp2 = getLocation(srcIp);
      }

      String dstp1 = "internal";
      String dstp2 = "internal";
      if ( dstIp == null ) {
        dstIp = "unknown";
        dstp1 = "unknown";
        dstp2 = "unknown";
      }
      else if ( !isInternal(dstIp) ) {
        dstp1 = "external";
        dstp2 = getLocation(dstIp);
      }

      String tag = null;
      if ( data != null )
        tag = "_i_" + data.replace(',', ';');

      String msg = constructMessage(String.valueOf(nextMsgId), ts + "000", srcp1, srcp2, srcIp, srcPort,
                                    dstp1, dstp2, dstIp, dstPort, 1, 0.0f, tag);
      nextMsgId++;
      loadpw.println(msg);
    }

    loadpw.close();
    sload.close();
    br.close();
  }

  private String getOssimValue ( String line, String tag ) {
    String searchStr = " " + tag + "='";
    int i = line.indexOf(searchStr);
    if ( i < 0 )
      return null;

    int j = line.indexOf("'", i + searchStr.length());
    if ( j < 0 )
      return null;

    return line.substring(i + searchStr.length(), j);
  }

  private String parseSyslog ( SimpleDateFormat slsdf, String line, int msgId, String year ) {
    try {
      String dateStr = line.substring(0, 15);
      java.util.Date d = slsdf.parse(year + " " + dateStr);
      int spaceInd = line.indexOf(' ', 16);

      StringBuilder sb = new StringBuilder();
      sb.append("sys");
      sb.append(String.valueOf(msgId));
      sb.append('\t');
      sb.append(String.valueOf(d.getTime()));
      sb.append('\t');
      sb.append("servers|");
      sb.append(line.substring(16, spaceInd));
      sb.append('|');

      int colonInd = line.indexOf(':', spaceInd + 1);
      String service = line.substring(spaceInd + 1, colonInd);
      String port = "-";
      int brackInd = service.indexOf('[');
      if ( brackInd > 0 ) {
        port = service.substring(brackInd + 1, service.length() - 1);
        service = service.substring(0, brackInd);
      }

      sb.append(service);
      sb.append('|');
      sb.append(port);
      sb.append('\t');

      sb.append("messages|syslog|-|-");

      sb.append("\t10|0\t_i_");
      sb.append(line.substring(colonInd + 2, line.length()));
      //System.out.println(sb.toString());
      return sb.toString();
    }
    catch ( Exception e ) {
      System.out.println("error parsing {" + line + "}: " + e);
      e.printStackTrace(System.out);
      return null;
    }
  }

  public void daemon () throws UnknownHostException, IOException, SecurityException,
                               InterruptedException, GeneralSecurityException {
    try {
      MessageForwarder mf = new MessageForwarder();
      mft = new Thread(mf);
      mft.start();
    }
    catch ( Exception e ) {
      System.out.println("error starting threads: " + e);
      System.exit(1);
    }

    ServerSocket ss = HubSock.getServerSocket(listenPort, overrideDir);
    while ( true ) {
      Socket s = ss.accept();
      PrintWriter pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
      sendNodeAttrs(pw);
      FeedSender fs = new FeedSender(s, pw);
      Thread t = new Thread(fs);
      t.start();
      synchronized ( feedSenders ) {
        Pro2be.thePro2be.connected = true;
        feedSenders.add(fs);
      }
    }
  }

  private void startCollecting () throws IOException, GeneralSecurityException {
    collector = new Collector(this);
    Thread collectorThread = new Thread(collector);
    collectorThread.start();

    Purger purger = new Purger(this);
    Thread purgerThread = new Thread(purger);
    purgerThread.start();

    ServerSocket ss = HubSock.getServerSocket(listenPort, overrideDir);
    System.out.println("Collector mode, listening on " + listenPort);
    while ( true ) {
      Socket s = ss.accept();
      PrintWriter pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));

      LoadSender fs = new LoadSender(s, pw, this);
      Thread t = new Thread(fs);
      t.start();
    }
  }

  private void sendTagDefs () {
    pw.println("__td_nmap|cube|.6|0|.8|spin");
  }

  public void run () {
    while ( true ) {
      Socket s = null;
      try {
        outQueue.clear();
        int port = Integer.parseInt(portStr);
        System.out.println("attempting to reach console at " + addrStr + ":" + port);
        s = new Socket(addrStr, port);
        pw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(s.getOutputStream(), true)));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));

        if ( probeTrackLevels != null ) {
          pw.println("track " + probeTrackLevels[0] + '|' + probeTrackLevels[1] +
                     '|' + probeTrackLevels[2] + '|' + probeTrackLevels[3]);
        }
        else
          pw.println("pcap_sniff");

        pw.flush();

        System.out.println("outbound connection established");
        sendTagDefs();
        connected = true;
        sendNodeAttrs(pw);
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

        if ( connected )
          System.out.println("error: " + e);
        connected = false;

	try {
          Thread.sleep(8000);
	}
	catch ( InterruptedException ie ) {}
      }
    }
  }

  private void monitor () throws IOException {
    boolean isGood = true;
    long lastPing = 0;
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 200 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.startsWith("pong") )
          isGood = false;
        else if ( line.startsWith("pong packdet ") )
          sendPacketDetail(line.substring(13, line.length()), pw);
        else if ( line.startsWith("pong nmap ") )
          launchNMAP(line);
        else if ( line.startsWith("pong pcap ") )
          writePcap(line);
        else if ( line.startsWith("pong push") )
          receiveFilters(line);
        lastPing = System.currentTimeMillis();
      }

      String str = outQueue.poll();
      if ( str != null )
        pw.println(str);
      else {
        try {
          Thread.sleep(50);
        }
	catch ( InterruptedException ie ) {}
      }
    }
  }

  private void sendPacketDetail ( String strId, PrintWriter pwp ) {
    try {
      if ( strId.startsWith("s") )
        return;

      long id = Long.parseLong(strId);
      PacketHolder pack = packetCache.get(new Long(id));
      if ( pack != null ) {
        pwp.print("__pd_");
        pwp.print(strId);
        pwp.print('\t');
        pwp.print(String.valueOf(pack.len));
        pwp.print('\t');
        pwp.print(Base64.encodeBase64String(pack.buf));
        pwp.println();
        pwp.flush();
      }
    }
    catch ( Exception e ) {
      e.printStackTrace(System.out);
    }
  }

  private void launchNMAP ( String line ) {
    String idPrefix = String.valueOf(nextNMAPId);
    nextNMAPId++;

    String[] split = line.split(" ");
    NMAPSnarfer ns = new NMAPSnarfer(this, split[2], split[3], idPrefix);
    Thread t = new Thread(ns);
    t.start();
  }

  public static byte uint ( int i ) {
    if ( i >= 128 )
      i = (128 - (i - 128)) * -1;
    return (byte)i;
  }

  private void writePcap ( String line ) {
    //System.out.println("writePcap with {" + line + "}");
    String[] split = line.substring(10, line.length()).split(",");
    int foundInCache = 0;
    try {
      FileOutputStream fos = new FileOutputStream(overrideDir + "dn.pcap");
      fos.write(uint(0xd4));
      fos.write(uint(0xc3));
      fos.write(uint(0xb2));
      fos.write(uint(0xa1));

      fos.write(uint(0x02));
      fos.write(uint(0x00));
      fos.write(uint(0x04));
      fos.write(uint(0x00));

      for ( int i = 0; i < 8; i++ )
        fos.write(uint(0x00));

      fos.write(uint(0xff));
      fos.write(uint(0xff));
      fos.write(uint(0x00));
      fos.write(uint(0x00));

      fos.write(uint(0x01));
      fos.write(uint(0x00));
      fos.write(uint(0x00));
      fos.write(uint(0x00));

      for ( String id : split )
        foundInCache += writePacket(fos, id);
      fos.close();
    }
    catch ( Exception e ) {
      System.out.println("error dumping pcap to " + overrideDir + "dn.pcap: " + e);
      e.printStackTrace(System.out);
    }
    System.out.println("requested: " + split.length + ", written: " + foundInCache);
  }

  private int writePacket ( FileOutputStream fos, String strId ) throws IOException {
    long id = Long.parseLong(strId);
    PacketHolder pack = packetCache.get(new Long(id));
    if ( pack == null )
      return 0;

    long seconds = pack.ts / 1000l;
    long micros = (pack.ts - seconds) * 1000l;
    writeLittleFour(fos, seconds);
    writeLittleFour(fos, micros);
    writeLittleFour(fos, pack.buf.length);
    writeLittleFour(fos, pack.buf.length);

    fos.write(pack.buf);
    return 1;
  }

  private void writeLittleFour ( FileOutputStream fos, long l ) throws IOException {
    int b1 = (int)(l / (256 * 256 * 256));
    l = l - (b1 * 256 * 256 * 256);

    int b2 = (int)(l / (256 * 256));
    l = l - (b2 * 256 * 256);

    int b3 = (int)(l / 256);
    int b4 = (int)(l - (b3 * 256));

    fos.write(uint(b4));
    fos.write(uint(b3));
    fos.write(uint(b2));
    fos.write(uint(b1));
  }

  private void receiveFilters ( String line ) {
    System.out.println("receiveFilters with {" + line + "}");
    try {
      if ( line.equals("pong push") ) {
        flags = null;
        filters = null;
        File f = new File(overrideDir + filterFname);
        f.delete();
        return;
      }

      String[] split = line.substring(10, line.length()).split("\t");
      loadFilters(split);
      PrintWriter pw = new PrintWriter(new FileWriter(overrideDir + filterFname));
      for ( String str : split )
        pw.println(str);
      pw.close(); 
    }
    catch ( Exception e ) {
      System.out.println("error receiving filters: " + e);
      e.printStackTrace(System.out);
    }
  }

  public static String buildProtPort ( String prot, String port ) {
    //if ( port < 1024 )
      return prot + '.' + port;
    //return prot;
  }

  private void commaCheck ( StringBuilder sb, String str ) {
    if ( sb.length() > 0 )
      sb.append(',');
    sb.append(str);
  }

  private String buildHier ( String str1, String str2, String str3, String str4 ) {
    StringBuilder sb = new StringBuilder();
    sb.append(str1);
    sb.append('|');
    sb.append(str2);
    sb.append('|');
    sb.append(str3);
    sb.append('|');
    sb.append(str4);
    return sb.toString();
  }

  public void attribNode ( String addr ) {
    if ( addr.equals("unknown") || addr.equals("n/a") )
      return;

    NodeAttrs na = nodeAttrs.get(addr);
    if ( na == null )
      nodeAttrQueue.offer(addr);
  }

  public synchronized long addToCache ( byte[] buf, int len, long ts ) {
    while ( totalPacketBytes > max_packet_bytes && packetCache.size() > 0 ) {
      byte[] purgeBuf = packetCache.pollFirstEntry().getValue().buf;
      totalPacketBytes -= purgeBuf.length;
    }

    if ( buf != null ) {
      packetCache.put(new Long(nextMsgId), new PacketHolder(buf, len, ts));
      totalPacketBytes += buf.length;
    }
    long ret = nextMsgId;
    nextMsgId++;
    return ret;
  }

  public boolean shouldFilter ( String srcp1, String srcp2, String srcp3, String srcp4,
                                 String dstp1, String dstp2, String dstp3, String dstp4,
                                 String tag ) {
    if ( filters == null )
      return false;

    String[] srcArray = new String[4];
    srcArray[0] = srcp1;
    srcArray[1] = srcp2;
    srcArray[2] = srcp3;
    srcArray[3] = srcp4;

    String[] dstArray = new String[4];
    dstArray[0] = dstp1;
    dstArray[1] = dstp2;
    dstArray[2] = dstp3;
    dstArray[3] = dstp4;

    String[] tagArray = null;
    if ( tag != null )
      tagArray = tag.split(",");

    if ( flags != null ) {
      for ( ProbeFilter pf : flags ) {
        if ( pf.match(srcArray, dstArray, tagArray, tag) )
          return false;
      }
    }

    for ( ProbeFilter pf : filters ) {    
      if ( pf.match(srcArray, dstArray, tagArray, tag) )
        return true;
    }

    return false;
  }

  public void sendMessage ( String id, String ts,
		             String srcp1, String srcp2, String srcp3, String srcp4,
                             String dstp1, String dstp2, String dstp3, String dstp4,
                             int len, float pri, String tag ) {
    sendMessage(constructMessage(id, ts, srcp1, srcp2, srcp3, srcp4,
                                 dstp1, dstp2, dstp3, dstp4, len, pri, tag));
  }

  public String constructMessage ( String id, String ts,
		             String srcp1, String srcp2, String srcp3, String srcp4,
                             String dstp1, String dstp2, String dstp3, String dstp4,
                             int len, float pri, String tag ) {
    StringBuffer sb = new StringBuffer();
    sb.append(id);
    sb.append('\t');
    sb.append(ts);
    sb.append('\t');
    sb.append(buildHier(srcp1, srcp2, srcp3, srcp4));
    sb.append('\t');
    sb.append(buildHier(dstp1, dstp2, dstp3, dstp4));
    sb.append('\t');
    sb.append(String.valueOf(len));
    sb.append('|');
    sb.append(String.valueOf(pri));
    if ( tag != null ) {
      sb.append('\t');
      sb.append(tag);
    }

    return sb.toString();
  }

  public void sendMessage ( String line ) {
    if ( connected )
      outQueue.offer(line);
  }

  public String getLocation ( String addr ) {
    String location = domainMap.get(addr);
    if ( location == null ) {
      location = lookupDomain(addr);
      domainMap.put(addr, location);
    }
    return location;
  }

  public boolean isInternal ( String addr ) {
    if ( localIps != null && localIps.contains(addr) )
      return true;

    if ( addr.startsWith("192.168") || addr.startsWith("10.") )
      return true;
    else if ( addr.startsWith("172.") && addr.charAt(6) == '.' ) {
      try {
        int i = Integer.parseInt(addr.substring(4, 6));
        if ( i >= 16 && i < 32 )
          return true;
      }
      catch ( Exception e ) {}
    }
    else if ( addr.toLowerCase().startsWith("fc") || addr.toLowerCase().startsWith("fd") )
      return true;

    return false;
  }

  private String lookupCountry ( String addr ) {
    try {
      URL url = new URL("http://ipinfo.io/" + addr + "/json");
      URLConnection conn = url.openConnection();
      conn.setConnectTimeout(6000);
      conn.setReadTimeout(5000);
      InputStream is = conn.getInputStream();

      int count = is.read(countryBuf);
      is.close();
      String json = new String(countryBuf, 0, count);
      return json;
    }
    catch ( Exception e ) {
      System.out.println("error looking up country for {" + addr + "}: " + e);
    }
    return null;
  }

  private String extractVar ( String json, String name ) {
    int i = json.indexOf("\"" + name + "\"");
    if ( i > -1 ) {
      int j = json.indexOf(":", i + 7);
      if ( j > -1 ) {
        int k = json.indexOf("\"", j + 1);
        if ( k > -1 ) {
          int l = json.indexOf("\"", k + 1);
          if ( l > -1 )
            return json.substring(k + 1, l);
        }
      }
    }
    return null;
  }

  private String lookupDomain ( String addr ) {
    String domain = "unknown";
    if ( noResolve )
      return domain;

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

  class PacketHolder {

    public byte[] buf;
    public int len;
    public long ts;

    public PacketHolder ( byte[] buf, int len, long ts ) {
      this.buf = buf;
      this.len = len;
      this.ts = ts;
    }
  }

  class AttrLookup implements Runnable {

    private Pro2be probe;

    public AttrLookup ( Pro2be probe ) {
      this.probe = probe;
    }

    public void run () {
      while ( !probe.die ) {
        String addr = probe.nodeAttrQueue.poll();
        if ( addr != null ) {
          if ( probe.nodeAttrs.containsKey(addr) )
            continue;

          NodeAttrs na = new NodeAttrs();
          probe.nodeAttrs.put(addr, na);

          boolean isInternal = probe.isInternal(addr);

          // look in critical assets list
          if ( probe.makeInternalCritical && isInternal )
            sendAttr(addr, "planet", "green", "appearance", na);

          if ( !isInternal && !addr.equals("255.255.255.255") && !addr.equals("unknown") ) {
            if ( probe.doCountry ) {
              String countryJson = probe.lookupCountry(addr);
              if ( countryJson != null ) {
                String countryName = probe.extractVar(countryJson, "country");
                if ( countryName != null )
                  sendAttr(addr, "country", countryName, "groupnode", na);

                String cityName = probe.extractVar(countryJson, "city");
                if ( cityName != null )
                  sendAttr(addr, "city", cityName, "text", na);

                String regionName = probe.extractVar(countryJson, "region");
                if ( regionName != null )
                  sendAttr(addr, "region", regionName, "text", na);
              }
            }
            //else
              //probe.nodeAttrQueue.offer(addr);
            // don't store the attr in na yet, no re-send mechanism yet
            // now get the ARIN
            // now get the IP reputation
          }
        }
        else if ( !probe.die ) {
          try {
            Thread.sleep(50);
          }
          catch ( Exception e ) {
            System.out.println("error in attrlookup sleep: " + e);
          }
        }
      }
    }

    private void sendAttr ( String addr, String name, String value, String type,
                            NodeAttrs na ) {
      na.store(type, name, value);
      String msg = buildNALine(addr, name, value, type);
      //System.out.println("attrMsg {" + msg + "}");
      probe.outQueue.offer(msg);
    }
  }

  class NodeAttrs {

    public HashMap<String, String> attrs = new HashMap<String, String>();

    public NodeAttrs () {
    }

    public void store ( String type, String name, String value ) {
      attrs.put(type + '-' + name, value);
    }
  }

  class Snorter implements Runnable {

    private Pro2be probe;
    private char[] alertLine = new char[5000];
    private int alertInd = 0;
    private int readerInd;
    // 06/20-15:28:49.352122
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd-HH:mm:ss.SSS");
    private long nextMsgId = 1l;
    private String year = null;

    public Snorter ( Pro2be probe ) {
      this.probe = probe;
    }

    public void run () {
      try {
        SimpleDateFormat ydf = new SimpleDateFormat("yyyy");
        year = ydf.format(new java.util.Date());

        String cmd = probe.snortStr;
        if ( cmd == null || cmd.trim().length() < 5 )
          return;

        System.out.println("executing command {" + cmd + "}");
        Process p = Runtime.getRuntime().exec(cmd);
        BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
        BufferedReader errBr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
        int c = -1;
        while ( !probe.die ) {
          if ( br.ready() ) {
            c = br.read();
            if ( c != -1 ) {
              char castc = (char)c;
              if ( castc == '\r' || castc == '\n' ) {
                if ( alertInd > 0 ) {
                  parseAlert();
                  alertInd = 0;
                }
              }
              else {
                alertLine[alertInd] = castc;
                alertInd++;
              }
            }
            else
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
        p.destroy();
      }
      catch ( Exception e ) {
        System.out.println("snorter thread error: " + e);
        e.printStackTrace(System.out);
      }
    }

    private String cleanIP ( String ip ) {
      if ( ip.indexOf(':') < 0 )
        return ip;
      String[] split = ip.toUpperCase().split(":");
      StringBuilder sb = new StringBuilder();
      boolean skipped = false;
      boolean prevSkipped = false;
      for ( int i = 0; i < split.length; i++ ) {
        if ( !split[i].equals("0") ) {
          if ( prevSkipped )
            sb.append(':');
          sb.append(split[i]);
          skipped = false;
        }
        else
          skipped = true;

        if ( !skipped && i < split.length - 1 )
          sb.append(':');

	prevSkipped = skipped;
      }
      return sb.toString();
    }

    private void parseAlert () throws ParseException {
      //System.out.println("alert {" + new String(alertLine, 0, alertInd) + "}");
      String id = "s" + nextMsgId;
      nextMsgId++;
      // 06/20-15:28:49.352122  [**] [1:33478:3] UDP happen [**] [Priority: 0] {UDP} 216.58.219.197:443 -> 192.168.1.154:65421
      java.util.Date d = sdf.parse(year + "/" + new String(alertLine, 0, 18));
      String ts = String.valueOf(d.getTime());
      StringBuilder tag = new StringBuilder();
      readerInd = 29;
      tag.append("_i_msgids=");
      tag.append(readUntilChar(']', 0));
      tag.append(',');
      readerInd++;
      tag.append(readUntilChar('[', 1));
      readerInd += 16;
      float pri = (Integer.parseInt(String.valueOf(alertLine[readerInd])) + 1) * .12f;
      readerInd += 4;

      String prot = readUntilChar('}', 0).toLowerCase();
      readerInd += 2;
      if ( prot.startsWith("ipv6-") )
        prot = prot.substring(5, prot.length());

      String srcIpRaw = readIPUntilChar(' ', 0);
      readerInd += 4;
      String dstIpRaw = readIPUntilChar(' ', 0);

      String src1 = "unknown";
      String src2 = "unknown";
      String src3 = "unknown";
      String src4 = "unknwon";
      String dst1 = "unknown";
      String dst2 = "unknown";
      String dst3 = "unknown";
      String dst4 = "unknown";

      if ( prot.equals("icmp") ) {
        src3 = cleanIP(srcIpRaw);
        dst3 = cleanIP(dstIpRaw);
        src4 = prot;
        dst4 = prot;
      }
      else {
        int colonInd = srcIpRaw.lastIndexOf(':');
        src3 = cleanIP(srcIpRaw.substring(0, colonInd));
        //int srcPort = Integer.parseInt(srcIpRaw.substring(colonInd + 1, srcIpRaw.length()));
        String srcPort = srcIpRaw.substring(colonInd + 1, srcIpRaw.length());

        colonInd = dstIpRaw.lastIndexOf(':');
        dst3 = cleanIP(dstIpRaw.substring(0, colonInd));
        //int dstPort = Integer.parseInt(dstIpRaw.substring(colonInd + 1, dstIpRaw.length()));
        String dstPort = dstIpRaw.substring(colonInd + 1, dstIpRaw.length());

        src4 = buildProtPort(prot, srcPort);
        dst4 = buildProtPort(prot, dstPort);

        tag.append(",_i_srcPort=");
        tag.append(String.valueOf(srcPort));
        tag.append(",_i_dstPort=");
        tag.append(String.valueOf(dstPort));
      }

      if ( fillLowers ) {
        if ( treeMode == TREEMODE_MAC ) {
          MacPair mp = null;
          int tries = 0;
          while ( mp == null && tries < 40 ) {
            mp = macCache.get(src3 + "|" + dst3);
            tries++;
            if ( mp == null ) {
              try {
                Thread.sleep(100);
              }
              catch ( Exception e ) {
                System.out.println("error sleeping before macpair retry: " + e);
              }
            }
          }

          if ( mp == null )
            System.out.println("null macpair for " + src3 + "|" + dst3 + ", tries = " + tries);
          else {
            src1 = mp.src;
            dst1 = mp.dst;
          }
        }

        src2 = "internal";
        boolean srcInternal = probe.isInternal(src3);
        if ( !srcInternal )
          src2 = getLocation(src3);

        dst2 = "internal";
        boolean dstInternal = probe.isInternal(dst3);
        if ( !dstInternal )
          dst2 = getLocation(dst3);

        if ( treeMode == TREEMODE_IP ) {
          //tag.append(",_i_srcMac=" + src1);
          //tag.append(",_i_dstMac=" + dst1);
          if ( srcInternal )
            src1 = "internal";
          else
            src1 = "external";

          if ( dstInternal )
            dst1 = "internal";
          else
            dst1 = "external";
        }

        ClientNet srcClientNet = checkClientNets(src3);
        if ( srcClientNet != null ) {
          src1 = srcClientNet.level1;
          src2 = srcClientNet.level2;
          src3 = srcClientNet.prefix + src3;
        }
        else {
          InternalNet srcNet = checkInternalNets(src3);
          if ( srcNet != null ) {
            src1 = srcNet.level1;
            src2 = srcNet.level2;
          }
        }

        ClientNet dstClientNet = checkClientNets(dst3);
        if ( dstClientNet != null ) {
          dst1 = dstClientNet.level1;
          dst2 = dstClientNet.level2;
          dst3 = dstClientNet.prefix + dst3;
        }
        else {
          InternalNet dstNet = checkInternalNets(dst3);
          if ( dstNet != null ) {
            dst1 = dstNet.level1;
            dst2 = dstNet.level2;
          }
        }
      }
      else {
        src1 = "_";
        src2 = "_";
        dst1 = "_";
        dst2 = "_";
      }

      String tagStr = tag.toString();
      if ( shouldFilter(src1, src2, src3, src4, dst1, dst2, dst3, dst4, tagStr) )
        return;

      probe.sendMessage(id, ts,
                        src1, src2, src3, src4,
                        dst1, dst2, dst3, dst4,
                        1, pri, tagStr);

      probe.attribNode(src3);
      probe.attribNode(dst3);
    }

    private String readUntilChar ( char c, int back ) {
      int i = 0;
      while ( alertLine[readerInd + i] != c )
        i++;
      int startInd = readerInd;
      readerInd += i;
      return new String(alertLine, startInd, i - back);
    }

    private String readIPUntilChar ( char c, int back ) {
      StringBuilder sb = new StringBuilder();
      int i = 0;
      int skipCount = 0;
      boolean lastIsColon = false;
      while ( alertLine[readerInd + i] != c && readerInd + i < alertInd ) {
        boolean skip = false;
        if ( alertLine[readerInd + i] == ':' ) {
          lastIsColon = true;
          skipCount = 0;
        }
        else {
          if ( lastIsColon && alertLine[readerInd + i] == '0' && skipCount < 3 ) {
            skip = true;
            skipCount++;
          }
          else
            lastIsColon = false;
        }

        if ( !skip )
          sb.append(alertLine[readerInd + i]);
        i++;
      }

      readerInd += i;
      return sb.toString();
    }
  }

  class FeedSender implements Runnable {

    private Socket s;
    private PrintWriter fspw;
    public LinkedBlockingQueue<String> queue = new LinkedBlockingQueue<String>(1000);

    public FeedSender ( Socket s, PrintWriter pw ) {
      this.s = s;
      this.fspw = pw;
    }

    public void run () {
      try {
        System.out.println("connection established from " + s.getInetAddress());
        monitor();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }

      synchronized ( Pro2be.thePro2be.feedSenders ) {
        Pro2be.thePro2be.feedSenders.remove(this);
        if ( Pro2be.thePro2be.feedSenders.size() <= 0 )
          Pro2be.thePro2be.connected = false;
      }
    }

    private void monitor () throws IOException, InterruptedException {
      BufferedReader fsbr = new BufferedReader(new InputStreamReader(s.getInputStream()));
      boolean isGood = true;
      long lastPing = 0;
      while ( fspw != null && isGood ) {
        if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 100 ) {
          fspw.println("ping");
          fspw.flush();
          String line = fsbr.readLine();
          if ( line == null || !line.startsWith("pong") )
            isGood = false;
          else if ( line.startsWith("pong packdet ") )
            sendPacketDetail(line.substring(13, line.length()), fspw);
          lastPing = System.currentTimeMillis();
        }

        String str = queue.poll(100, TimeUnit.MILLISECONDS);
        if ( str != null ) {
          fspw.println(str);
          //fspw.flush();
        }
      }
      System.out.println("closing connection to " + s.getInetAddress());
      fsbr.close();
      fspw.close();
      s.close();
    }
  }

  class MessageForwarder implements Runnable {

    public MessageForwarder () {
    }

    public void run () {
      try {
        while ( !Pro2be.thePro2be.die ) {
          String str = Pro2be.thePro2be.outQueue.poll(100, TimeUnit.MILLISECONDS);
          if ( str == null ) {
            continue;
	  }

	  synchronized ( Pro2be.thePro2be.feedSenders ) {
            for ( FeedSender fs : Pro2be.thePro2be.feedSenders ) {
              fs.queue.offer(str);
            }
	  }
	}
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }
  }

  class NMAPSnarfer implements Runnable {

    private Pro2be probe;
    private String ip;
    private String prefix;
    private StringBuilder msgBuilder = null;
    private int nextId = 1;
    private String idPrefix;
    private String attrBegin = "\t20|0\tnmap";
    private byte[] alertLine = new byte[2000];
    private int alertInd = 0;

    public NMAPSnarfer ( Pro2be probe, String ip, String prefix, String idPrefix ) {
      this.probe = probe;
      this.ip = ip;
      this.prefix = prefix;
      this.idPrefix = idPrefix;
    }

    public void run () {
      Process p = null;
      InputStream is = null;
      String cmd = "nmap -O -sC " + ip;
      try {
        System.out.println("running {" + cmd + "}");
        p = Runtime.getRuntime().exec(cmd);
        is = p.getInputStream();
        int c;
        boolean gotPort = false;
        boolean nomorePort = false;
        while ( !probe.die && ((c = is.read()) != -1) ) {
          if ( c == '\r' || c == '\n' ) {
            if ( alertInd > 0 ) {
              String line = new String(alertLine, 0, alertInd);
              System.out.println(line);
              try {
                if ( nomorePort )
                  addGeneral(line);
	        else if ( gotPort ) {
                  if ( line.startsWith("|") )
                    addPortDetails(line);
                  else {
                    int slashInd = line.indexOf('/');
                    if ( slashInd > 0 && slashInd < 10 )
                      addPort(line, slashInd);
                    else {
                      nomorePort = true;
                      addGeneral(line);
                    }
                  }
                }
                else if ( line.startsWith("PORT") )
                  gotPort = true;
                else
                  addGeneral(line);
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
	}
      }
      catch ( Exception e ) {
        System.out.println("nmap thread error: " + e);
        e.printStackTrace(System.out);
      }
      finally {
        flushPrev();
        try {
          if ( is != null )
            is.close();
          if ( p != null )
            p.destroy();
          System.out.println("process {" + cmd + "} cleaned up");
        }
        catch ( Exception e ) {
          System.out.println("error cleaning up {" + cmd + "}: " + e);
          e.printStackTrace(System.out);
        }
      }
    }

    private void addPortDetails ( String line ) {
      msgBuilder.append(',');
      msgBuilder.append("_i_");
      msgBuilder.append(line.substring(2, line.length()).trim().replace(',', ';'));
    }

    private void addPort ( String line, int slashInd ) {
      flushPrev();
      
      int j = line.indexOf(' ', slashInd);
      if ( j < 0 )
        j = line.length();
      String port = line.substring(0, slashInd);
      port += line.substring(slashInd + 1, j);
      msgBuilder.append(port);
      msgBuilder.append(attrBegin);
      if ( j + 1 < line.length() )
        msgBuilder.append(",_i_" + line.substring(j + 1, line.length()).trim().replace(',', ';'));
    }

    private void addGeneral ( String line ) {
      flushPrev();
      msgBuilder.append("nmap_attrs");
      msgBuilder.append(attrBegin);
      msgBuilder.append(',');
      msgBuilder.append(line.trim().replace(',', ';'));
    }

    private void flushPrev () {
      if ( msgBuilder != null && msgBuilder.length() > 0 ) {
        probe.sendMessage(msgBuilder.toString());
        System.out.println(msgBuilder.toString());
      }

      msgBuilder = new StringBuilder();
      msgBuilder.append('n');
      msgBuilder.append(idPrefix);
      msgBuilder.append('.');
      msgBuilder.append(String.valueOf(nextId));
      nextId++;
      msgBuilder.append('\t');
      msgBuilder.append(String.valueOf(System.currentTimeMillis()));
      msgBuilder.append('\t');
      msgBuilder.append("actions|nmap|nmap|nmap\t");
      msgBuilder.append(prefix);
      msgBuilder.append('|');
    }
  }
}
