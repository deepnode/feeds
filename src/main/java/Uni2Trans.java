import java.util.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

public class Uni2Trans {

  private BufferedReader inbr = null;

  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private HashMap<String, String> domainMap = new HashMap<String, String>();
  private ArrayList<TSSubnet> subnets = new ArrayList<TSSubnet>();
  private boolean isWindows = false;

  public static void main ( String[] args ) {
    try {
      Uni2Trans sniff = new Uni2Trans();
      sniff.go();
    }
    catch ( Exception e ) {
      System.out.println("error: " + e);
      e.printStackTrace(System.out);
    }
  }

  public Uni2Trans () throws java.io.IOException {
    inbr = new BufferedReader(new InputStreamReader(System.in));
    System.out.println("Listening for unified2 alerts...");
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
        s = new Socket(vizHost, 4021);
        pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("unified2");
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
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();
      }
 
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
}


