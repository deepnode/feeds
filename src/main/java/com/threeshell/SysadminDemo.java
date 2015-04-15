package com.threeshell;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.WindowConstants;
import java.util.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.concurrent.LinkedBlockingQueue;

public class SysadminDemo extends JFrame implements Runnable {

  private PrintWriter pw;
  private BufferedReader br;
  private SimpleDateFormat sdf = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss.S");
  public static final String[] nets = {"grp.sys", "internal", "external", "datacenter"};
  public static final String[] tlds = {"net", "com", "gov", "org"};
  public static final String[] domPieces = {"wa", "ko", "ta", "no", "shi", "mi", "ru", "ja", "de", "su", "fu", "y"};
  public static final String[] floorDoms = {"floor.1", "floor.2", "floor.3"};
  public static final String[] subnets = {"192.168.50", "192.168.51", "10.34"};
  public static final String[] dchosts = {"datacenter|192.168.50|!Authoritative_Database",
                                          "datacenter|192.168.50|!Medical_Records",
                                          "datacenter|192.168.50|Fileserver_01",
                                          "datacenter|192.168.50|Fileserver_02",
                                          "datacenter|192.168.51|!Application_Gateway",
                                          "datacenter|192.168.51|!Creditcard_Transactions",
                                          "datacenter|192.168.51|Web03",
                                          "datacenter|192.168.51|Web04",
                                          "datacenter|10.34|!HR_Database",
                                          "datacenter|10.34|SRCS_Database",
                                          "datacenter|10.34|SRCS_Appserver",
                                          "datacenter|10.34|Domain_Controller",
                                          "datacenter|10.34|FW01"};
  public static final String[] dcnames = {"!Authoritative_Database",
                                          "!Medical_Records",
                                          "Fileserver_01",
                                          "Fileserver_02",
                                          "!Application_Gateway",
                                          "!Creditcard_Transactions",
                                          "Web03",
                                          "Web04",
                                          "!HR_Database",
                                          "SRCS_Database",
                                          "SRCS_Appserver",
                                          "Domain_Controller",
                                          "FW01"};
  public static final String[] msgs = {"tcp", "udp"};
  public static final String[] ports = {"sshd", "nfs", "httpd"};
  public static final String[] sysadmins = {"Jane", "Eve", "Quorra", "Aang", "Edward", "Bernice", "Bill"};
  public LinkedBlockingQueue<String> q = new LinkedBlockingQueue<String>(50);
  public ArrayList<String> allHosts = new ArrayList<String>();
  public ArrayList<String> edHosts;
  public ArrayList<String> sysHosts;
  public ArrayList<String> datacenterHosts;
  public ArrayList<String> internalHosts;
  public ArrayList<String> externalHosts;
  private String trickleFrom = null;
  private String trickleTo = null;
  private LinkedList<String> shapes = new LinkedList<String>();
  private float[] FLOOR_HEIGHTS;
  private long nextMsgId = 1l;
  private long totalBytes = 0l;
  private long start;

  public static void main ( String[] args ) {
    EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            SysadminDemo demo = new SysadminDemo();
            demo.setVisible(true);
            demo.setup();
	    Thread t = new Thread(demo);
            t.start();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
    });
  }

  public SysadminDemo () {
       setTitle("Deep Node Demo Feed");
       setSize(500, 80);
       setLocationRelativeTo(null);
       setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
  }

  private void addShape ( String name, String type, String shape, float r, float g, float b, float a,
                          float xloc, float yloc, float zloc, float xscale, float yscale, float zscale,
                          float xrot, float yrot, float zrot, String effects, String ref ) {
    String str = name + '|' + type + '|' + shape + '|' + r + '|' + g + '|' + b + '|' + a + '|' +
                 xloc + '|' + yloc + '|' + zloc + '|' + xscale + '|' + yscale + '|' + zscale + '|' +
                 xrot + '|' + yrot + '|' + zrot + '|' + effects + '|' + ref;
    shapes.add(str);
  }

  public void setup () {
       addWindowListener(new WindowAdapter()
        {
            @Override
            public void windowClosing(WindowEvent e)
            {
                System.out.println("Closed");
                e.getWindow().dispose();
		System.exit(0);
            }
        });

    // name|type|shape|r|g|b|a|xloc|yloc|zloc|xscale|yscale|zscale|xrot|yrot|zrot|effects|ref
    FLOOR_HEIGHTS = new float[3];
    FLOOR_HEIGHTS[0] = 0.4f;
    FLOOR_HEIGHTS[1] = 1.6f;
    FLOOR_HEIGHTS[2] = 2.8f;
    float[][] GRID_COORDS = new float[9][2];
    for ( int gcrow = 1; gcrow < 4; gcrow++ ) {
      for ( int gccol = 1; gccol < 4; gccol++ ) {
        GRID_COORDS[(gcrow - 1) * 3 + (gccol - 1)][0] = -12.5f + gcrow * (5.0f / 3.0f);
        GRID_COORDS[(gcrow - 1) * 3 + (gccol - 1)][1] = -1.5f + gccol * 1.0f;
      }
    }

    //shapes.add("floor1|down|cube|0.3|0.5|0.8|0.2|-4.0|" + FLOOR_HEIGHTS[0] + "|0|5.0|.05|3|0.0|0.0|0.0||floor1");
    //shapes.add("floor2|down|cube|0.3|0.5|0.8|0.2|-4.0|" + FLOOR_HEIGHTS[1] + "|0|5.0|.05|3|0.0|0.0|0.0||floor2");
    //shapes.add("floor3|down|cube|0.3|0.5|0.8|0.2|-4.0|" + FLOOR_HEIGHTS[2] + "|0|5.0|.05|3|0.0|0.0|0.0||floor3");

    internalHosts = new ArrayList<String>();
    int employeeNum = 1;
    for ( int i = 0; i < floorDoms.length; i++ ) {
      for ( int j = 0; j < 8 - i; j++ ) {
        String ref = "internal|" + floorDoms[i] + "|10.0." + i + "." + j;
        internalHosts.add(ref);
	addShape("emp" + employeeNum, "down", "sphere", 0.8f, 0.4f, 0.1f, 1.0f, GRID_COORDS[j][0], FLOOR_HEIGHTS[i] + 0.3f,
                 GRID_COORDS[j][1], 0.2f, 0.2f, 0.2f, 0.0f, 0.0f, 0.0f, "", ref.replace("|", "\t")); 
        employeeNum++;
      }
    }

    externalHosts = new ArrayList<String>();
    for ( int i = 0; i < 11; i++ ) {
      String dom = getRand(domPieces) + getRand(domPieces) + getRand(domPieces) + getRand(domPieces) + "." + getRand(tlds);
      for ( int j = 0; j < 1 + Math.random() * 2; j++ )
        externalHosts.add("external|" + dom + "|" + i + "." + (int)Math.floor(Math.random() * 256d) + 
			                                "." + (int)Math.floor(Math.random() * 256d) + "." + j * 3);
    }
    trickleTo = "external|" + getRand(domPieces) + getRand(domPieces) + getRand(domPieces) +
                            getRand(domPieces) + "." + getRand(tlds) + "|12.66.66.233|udp53";

    addShape("external", "down", "sphere", .2f, .8f, 1.0f, .4f, -3.0f, .8f,
             -3.6f, 1.41f, 1.41f, 1.41f, 0.0f, 0.0f, 0.0f, "", "external");

    datacenterHosts = new ArrayList<String>();
    float xpos = 4.0f;
    float zpos = 3.0f;
    for ( int i = 0; i < dchosts.length; i++ ) {
      datacenterHosts.add(dchosts[i]);
      float r = 1.0f;
      float g = 1.0f;
      float b = 0f;
      if ( dchosts[i].startsWith("c") ) {
        r = .1f;
	g = .6f;
	b = .7f;
      }

      addShape(dcnames[i], "down", "cube", r, g, b, 1.0f, xpos, 0.7f,
               zpos, 0.25f, 0.25f, 0.25f, 0.0f, 0.0f, 0.0f, "",
               dchosts[i].replace("|", "\t")); 

      xpos -= 1.0f;
      if ( i == 4 ) {
        xpos = 4.0f;
        zpos -= 1.0f;
      }
      else if ( i == 8 ) {
        xpos = 4.0f;
        zpos -= 1.0f;
      }
    }      

    edHosts = new ArrayList<String>();
    sysHosts = new ArrayList<String>();
    xpos = 7.5f;
    for ( int i = 0; i < sysadmins.length; i++ ) {
      float ypos = 0.4f;
      xpos += .6f;
      for ( int j = 0; j < 1 + Math.random() * 3; j++ ) {
        String str = "grp.sys|" + sysadmins[i] + "|10." + i + "." + (i * 2 + 3) + "." + j;
	sysHosts.add(str);
	if ( i == 4 )
          edHosts.add(str);
	else if ( i == 1 && trickleFrom == null )
          trickleFrom = str + "|udp";

        String ref = str.replace("|", "\t");
        addShape(ref, "down", "sphere", .9f, .2f, .2f, .7f, xpos, ypos,
                 -1.0f, 0.21f, 0.21f, 0.21f, 0.0f, 0.0f, 0.0f, "", ref);
        ypos += .38f;	
      }
    }

    addHosts(internalHosts);
    addHosts(externalHosts);
    addHosts(datacenterHosts);
    addHosts(sysHosts);
  }

  private void addHosts ( ArrayList<String> hosts ) {
    for ( String s : hosts )
      allHosts.add(s);
  }

  public void run () {
    start = System.currentTimeMillis();

    Thread t = new Thread(new StreamMonitor(this, 80000, 60000, 5000, 1000, datacenterHosts, sysHosts));
    t.start();

    Thread t3 = new Thread(new StreamMonitor(this, 8000, 500, 10000, 3000, externalHosts, internalHosts));
    t3.start();

    Thread t4 = new Thread(new StreamMonitor(this, 10000, 2000, 1200, 300, datacenterHosts, internalHosts));
    t4.start();

    Thread t7 = new Thread(new StreamMonitor(this, 10000, 2000, 900, 100, datacenterHosts, edHosts));
    t7.start();

    Thread t5 = new Thread(new StreamMonitor(this, 10000, 2000, 2600, 4000, allHosts, allHosts));
    t5.start();

    Thread t6 = new Thread(new StreamMonitor(this, 40000, 10000, 800, 200, datacenterHosts, edHosts));
    t6.start();

    Thread t2 = new Thread(new SpitMonitor(this));
    t2.start();

    Thread t8 = new Thread(new TrickleMonitor(this, trickleFrom, trickleTo));
    t8.start();

    while ( true ) {
      Socket s = null;
      try {
        s = new Socket("localhost", 4021);
        pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("demo_alert");
        pw.flush();
        q.clear();
        for ( String str : shapes )
          pw.println("__rd_" + str);
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

  private void monitor () throws IOException, InterruptedException {
    boolean isGood = true;
    long lastPing = 0;
    pw.println("__td_tag1|sphere|.8|.7|0.0|pulse");
    pw.println("__td_tag2|torus|1.0|.1|.1|spin");
    pw.println("__td_tag3|cube|.1|.3|1.0|none");  
    pw.println("__td_tag4|cone|.2|.8|.2|spin,pulse");  
    pw.println("__td_helo|text|.2|.8|.7|spin");  
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();

	if ( lastPing - start > 10000 && lastPing - start < 20000 )
	  System.out.println("bytes: " + totalBytes + ", secs: " + ((lastPing - start) / 1000) + ", b/s = " + (totalBytes / ((lastPing - start) / 1000)));
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

    private SysadminDemo da;

    public SpitMonitor ( SysadminDemo da ) {
      this.da = da;
    }

    public void run () {
      try {
        while ( true ) {
          for ( int i = 0; i < (int)Math.floor(Math.random() * 10d); i++ ) {
            // <categry>|<subcat>|<subcat>\t<category>|<subcat>\t<meas_name>|<meas_value>|<meas_name>|<meas_value>
            String from = da.getRandomNode(allHosts, true);
            String to = da.getRandomNode(allHosts, false);
            float level = 0.0f;
            if ( Math.random() > .91d )
              level = .6f;

            StringBuffer sb = new StringBuffer(from);
            sb.append('\t');
            sb.append(to);
            sb.append('\t');

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

    private SysadminDemo da;
    private String a;
    private String b;
    private int min;
    private int add;
    private long minDuration;
    private long ranDuration;
    private ArrayList<String> bigFromHosts;
    private ArrayList<String> smallFromHosts;

    public StreamMonitor ( SysadminDemo da, int min, int add, long minDuration, long ranDuration,
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

  class TrickleMonitor implements Runnable {

    private SysadminDemo da;
    private String from;
    private String to;

    public TrickleMonitor ( SysadminDemo da, String from, String to ) {
      this.da = da;
      this.from = from;
      this.to = to;
    }

    public void run () {
      try {
        while ( true ) {
          da.buildPacket(from, to, 20000, 0);
          Thread.sleep(60000);
        }
      }
      catch ( Exception e ) {
        System.out.println("tricklemonitor dead: " + e);
        e.printStackTrace(System.out);
      }
    }
  }

  public void buildPacket ( String from, String to, int minBytes, int addBytes ) {
    float level = 0.0f;
    //if ( Math.random() > .98d )
    //  level = .6f;

    StringBuffer sb = new StringBuffer();
    sb.append(getNextMsgId());
    sb.append('\t');
    sb.append(String.valueOf(System.currentTimeMillis()));
    sb.append('\t');
    sb.append(from);
    sb.append('\t');
    sb.append(to);
    sb.append('\t');

    long bytes = minBytes + (int)Math.floor(Math.random() * (double)addBytes);
    totalBytes += bytes;
    sb.append(String.valueOf(bytes));
    sb.append('|');
    sb.append(String.valueOf(level));

    String str = sb.toString();
    offerToQueue(str);
  }

  public String getNextMsgId () {
    String id = null;
    synchronized ( this ) {
      id = String.valueOf(nextMsgId);
      nextMsgId++;
    }
    return id;
  }

  public void spitPacket ( StringBuffer sbOrig, float level ) {
    StringBuffer sb = new StringBuffer();
    sb.append(getNextMsgId());
    sb.append('\t');
    sb.append(String.valueOf(System.currentTimeMillis()));
    sb.append('\t');
    sb.append(sbOrig);

    long bytes = (int)Math.floor(Math.random() * 100000d);
    totalBytes += bytes;
    sb.append(String.valueOf(bytes));
    sb.append('|');

    String tag = "";
    double dr = Math.random();
    //if ( dr < .1d )
    //  tag = "tag1";
    //else if ( dr < .3d )
    //  tag = "tag2";
    //else if ( dr < .36d )
    //  tag = "tag3";
    //else if ( dr < .46d )
    //  tag = "tag4";
    //else if ( dr < .56d )
    //  tag = "helo";
    
    if ( dr < .1d ) {
      tag = "tag2";
      level = .5f;
    }
    else if ( dr < .15d ) {
      tag = "IDS:scan";
      level = 1f;
    }

    sb.append(String.valueOf(level));
    sb.append('\t');
    sb.append(tag);

    String str = sb.toString();
    offerToQueue(str);
  }

  private void offerToQueue ( String msg ) {
    q.offer(msg);
  }

  private void offerToQueueTake ( String msg ) {
    if ( !q.offer(msg) ) {
      try {
        q.take();
        q.offer(msg);
      }
      catch ( InterruptedException ie ) {
        System.out.println("interrupted trying to shift the queue: " + ie);
      }
    }
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


