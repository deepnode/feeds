package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.concurrent.LinkedBlockingQueue;

public class SmallDemo {

  private PrintWriter pw;
  private BufferedReader br;
  private SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.S");
  public static final String[] nets = {"grp.sys", "internal", "external", "datacenter"};
  public static final String[] tlds = {"net", "com", "gov", "org"};
  public static final String[] domPieces = {"wa", "ko", "ta", "no", "shi", "mi", "ru", "ja", "de", "su", "fu", "y"};
  public static final String[] floorDoms = {"floor.1", "floor.2", "floor.3", "floor.4"};
  public static final String[] subnets = {"192.168.50", "192.168.51", "192.168.52", "10.34"};
  public static final String[] serverTypes = {"web", "db", "fw", "file", "app"};
  public static final String[] msgs = {"tcp", "udp"};
  public static final String[] ports = {"sshd", "nfs", "httpd"};
  public static final String[] sysadmins = {"Jane", "Eve", "Sam", "Quorra", "Aang", "Edward", "Bernice", "Jacqueline", "Larry", "Bill"};
  public static final LinkedBlockingQueue<String> q = new LinkedBlockingQueue<String>();
  public ArrayList<String> allHosts = new ArrayList<String>();
  public ArrayList<String> edHosts;
  public ArrayList<String> sysHosts;
  public ArrayList<String> datacenterHosts;
  public ArrayList<String> internalHosts;
  public ArrayList<String> externalHosts;

  public static void main ( String[] args ) {
    try {
      SmallDemo demo = new SmallDemo();
      demo.setup();
      demo.go();
    }
    catch ( Exception e ) {
      System.out.println("error: " + e);
      e.printStackTrace(System.out);
    }
  }

  public SmallDemo () {
  }

  public void setup () {
    datacenterHosts = new ArrayList<String>();
    for ( int i = 0; i < subnets.length; i++ ) {
      for ( int j = 0; j < 4 + i; j++ )
        datacenterHosts.add("datacenter|" + subnets[i] + "|" + getRand(serverTypes) + j);
    }

    edHosts = new ArrayList<String>();
    sysHosts = new ArrayList<String>();
    for ( int i = 0; i < sysadmins.length; i++ ) {
      for ( int j = 0; j < 1 + Math.random() * 3; j++ ) {
        String str = "grp.sys|" + sysadmins[i] + "|10." + i + "." + (i * 2 + 3) + "." + j;
	sysHosts.add(str);
	if ( i == 5 )
          edHosts.add(str);
      }
    }

    addHosts(datacenterHosts);
    addHosts(sysHosts);
  }

  private void addHosts ( ArrayList<String> hosts ) {
    for ( String s : hosts )
      allHosts.add(s);
  }

  public void go () throws UnknownHostException, IOException, SecurityException,
                           InterruptedException {
    while ( true ) {
      Socket s = null;
      try {
        Thread t = new Thread(new StreamMonitor(this, 80000, 60000, 5000, 1000, datacenterHosts, sysHosts));
	t.start();

        Thread t7 = new Thread(new StreamMonitor(this, 10000, 2000, 900, 100, datacenterHosts, edHosts));
	t7.start();

        Thread t5 = new Thread(new StreamMonitor(this, 10000, 2000, 1600, 3000, allHosts, allHosts));
	t5.start();

        Thread t6 = new Thread(new StreamMonitor(this, 40000, 10000, 800, 200, datacenterHosts, edHosts));
	t6.start();

        Thread t2 = new Thread(new SpitMonitor(this));
	t2.start();

        s = new Socket("localhost", 4021);
        pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("demo_alert");
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

  private void monitor () throws IOException, InterruptedException {
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

      String str = q.poll();
      if ( str != null ) {
        pw.println(str);
	pw.flush();
      }
      else
        Thread.sleep(20);
    }
  }

  class SpitMonitor implements Runnable {

    private SmallDemo da;

    public SpitMonitor ( SmallDemo da ) {
      this.da = da;
    }

    public void run () {
      try {
        while ( true ) {
          for ( int i = 0; i < (int)Math.floor(Math.random() * 10d); i++ ) {
            // <categry>|<subcat>|<subcat>\t<category>|<subcat>\t<meas_name>|<meas_value>|<meas_name>|<meas_value>
            StringBuffer sb = new StringBuffer(da.getRandomNode(allHosts, true));
            sb.append('\t');
            sb.append(da.getRandomNode(allHosts, false));
            sb.append('\t');

            float level = 0.0f;
            if ( Math.random() > .7f )
              level = .7f + (float)Math.floor(.3f * Math.random());

            for ( int j = 0; j < (int)Math.floor(Math.random() * 30d); j++ ) {
              da.spitPacket(sb, level);
	      Thread.sleep((int)Math.floor(Math.random() * 160d));
            }
          }
          Thread.sleep((long)Math.floor(Math.random() * 3000d + 50d));
        }
      }
      catch ( Exception e ) {
        System.out.println("streammonitor dead: " + e);
      }
    }
  }

  class StreamMonitor implements Runnable {

    private SmallDemo da;
    private String a;
    private String b;
    private int min;
    private int add;
    private long minDuration;
    private long ranDuration;
    private ArrayList<String> bigFromHosts;
    private ArrayList<String> smallFromHosts;

    public StreamMonitor ( SmallDemo da, int min, int add, long minDuration, long ranDuration,
		           ArrayList<String> bigFromHosts, ArrayList<String> smallFromHosts ) {
      this.da = da;
      this.min = min;
      this.add = add;
      this.minDuration = minDuration;
      this.ranDuration = ranDuration;
      this.bigFromHosts = bigFromHosts;
      this.smallFromHosts = smallFromHosts;
    }

    public void run () {
      try {
        while ( true ) {
          a = da.getRandomNode(bigFromHosts, true);
          b = da.getRandomNode(smallFromHosts, true);
          long stop = System.currentTimeMillis() + minDuration + (long)Math.floor(Math.random() * (double)ranDuration);
          while ( System.currentTimeMillis() < stop ) {
            da.buildPacket(a, b, min, add);
            da.buildPacket(b, a, min / 20, add / 20);
            Thread.sleep((long)Math.floor(Math.random() * 100d + 50d));
          }
          Thread.sleep(minDuration / 2 + (long)Math.floor(Math.random() * (double)ranDuration));
        }
      }
      catch ( Exception e ) {
        System.out.println("streammonitor dead: " + e);
        e.printStackTrace(System.out);
      }
    }
  }

  public void buildPacket ( String from, String to, int minBytes, int addBytes ) {
    // <categry>|<subcat>|<subcat>\t<category>|<subcat>\t<meas_name>|<meas_value>|<meas_name>|<meas_value>
    StringBuffer sb = new StringBuffer(from);
    sb.append('\t');
    sb.append(to);
    sb.append('\t');

    float level = 0.0f;
    sb.append(String.valueOf(minBytes + (int)Math.floor(Math.random() * (double)addBytes)));
    sb.append('|');
    sb.append(String.valueOf(level));

    String str = sb.toString();
    q.offer(str);
  }

  public void spitPacket ( StringBuffer sb, float level ) {
    sb.append(String.valueOf((int)Math.floor(Math.random() * 100000d)));
    sb.append('|');
    sb.append(String.valueOf(level));

    String str = sb.toString();
    q.offer(str);
  }

  public String getRand ( String[] src ) {
    return src[(int)Math.floor(Math.random() * (double)src.length)];
  }

  public String getRandomNode ( ArrayList<String> hosts, boolean usePorts ) {
    String h = hosts.get((int)Math.floor(Math.random() * hosts.size()));
    String svc = null;
    if ( usePorts )
      svc = getRand(ports);
    else
      svc = getRand(msgs);
    return h + "|" + getRand(ports);
  }
}


