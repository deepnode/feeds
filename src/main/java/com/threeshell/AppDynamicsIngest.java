package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.*;
import java.net.UnknownHostException;
import java.text.*;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;
import org.apache.commons.codec.binary.Base64;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JTextArea;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class AppDynamicsIngest extends JFrame {

  private BufferedReader inbr = null;
  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private static HashMap<String, String> domainMap = new HashMap<String, String>();
  private static boolean isWindows = false;
  private JTextArea requestText = new JTextArea();
  private JButton searchButton = new JButton("get");
  private JPasswordField passwordText = new JPasswordField(20);
  private JTextField userText = new JTextField(25);
  private JTextField urlBeginText = new JTextField(50);
  public ADApplication[] applications = null;

  private long nextMsgId = 1l;
  public static AppDynamicsIngest adIngest = null;
  public String overrideDir;
  public String configFname;
  public HashMap<String, ADNode> nodes = new HashMap<String, ADNode>();

  public static void main ( String[] args ) {
    EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            adIngest = new AppDynamicsIngest();
            adIngest.setVisible(true);
            adIngest.setup();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
    });
  }

  public AppDynamicsIngest () {
       setTitle("Deep Node AppDynamics Ingester");
       setSize(660, 260);
       setLocationRelativeTo(null);
       setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
       getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
  }

  public void setup () throws FileNotFoundException, IOException {
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

    String os = System.getProperty("os.name").toLowerCase();
    if ( os.indexOf("win") > -1 )
      isWindows = true;

    JPanel passPanel = new JPanel();
    passPanel.setSize(640, 100);
    passPanel.add(new JLabel("user"));
    passPanel.add(userText);
    passPanel.add(new JLabel("pass"));
    passPanel.add(passwordText);
    add(passPanel);

    JPanel urlBeginPanel = new JPanel();
    urlBeginPanel.setSize(640, 100);
    urlBeginPanel.add(new JLabel("url begin"));
    urlBeginPanel.add(urlBeginText);
    add(urlBeginPanel);

    requestText.setLineWrap(true);
    add(requestText);
    add(searchButton);
    searchButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        try {
          doSearch();
        }
        catch ( IOException ie ) {
          ie.printStackTrace(System.out);
        }
      }
    });

    overrideDir = System.getProperty("user.home") + File.separator + ".deepnode";
    createIfNotExist(overrideDir);
    overrideDir += File.separator;
    configFname = "appdynamics_ingest.properties";
    File configf = new File(overrideDir + configFname);
    if ( configf.exists() )
      readConfigFile(new FileReader(overrideDir + configFname));
    else {
      requestText.setText("time-range-type=BEFORE_NOW&duration-in-mins=10");
    }
  }

  public static void createIfNotExist ( String dirName ) throws IOException {
    File dir = new File(dirName);
    if ( !dir.exists() ) {
      System.out.println("creating directory " + dirName);
      dir.mkdir();
    }
  }

  public void doSearch () throws IOException {
    writeConfigFile();
    SearchRun sr = new SearchRun();
    Thread t = new Thread(sr);
    t.start();
  }

  private void readConfigFile ( Reader r ) throws IOException {
    Properties props = new Properties();
    props.load(r);
    r.close();
    requestText.setText(props.getProperty("request"));
    userText.setText(props.getProperty("user"));
    urlBeginText.setText(props.getProperty("urlBegin"));
  }

  private void writeConfigFile () throws IOException {
    PrintWriter pw = new PrintWriter(new FileWriter(overrideDir + configFname));
    pw.println("request=" + requestText.getText());
    pw.println("user=" + userText.getText());
    pw.println("urlBegin=" + urlBeginText.getText());
    pw.close();
  }

  public static String getLocation ( String addr ) {
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

  public static String lookupDomain ( String addr ) {
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

  class SearchRun implements Runnable {

    private PrintWriter pw = null;
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S zzz");

    public void run () {
      try {
        if ( applications == null )
          loadEntityTree();

        TreeMap<Long, ADSnapshot> eventMap = new TreeMap<Long, ADSnapshot>();
        String strUrl = urlBeginText.getText() + "/controller/rest/applications/";
        for ( ADApplication app : applications ) {
          String strFullUrl = strUrl + app.name + "/request-snapshots?" + requestText.getText() + "&need-props=true&output=JSON";
          ADSnapshot[] events = (ADSnapshot[])fetchObj(strFullUrl, ADSnapshot[].class);
          for ( ADSnapshot event : events ) {
            event.app = app;
            eventMap.put(new Long(event.localStartTime), event);
          }
        }

        Socket s = new Socket("localhost", 4021);
        pw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
        pw.println("appdynamics_ingest");
        pw.flush();

        long prevTime = 0l;
        for ( Map.Entry<Long, ADSnapshot> entry : eventMap.entrySet() ) {
          //System.out.println("msg: " + entry.getValue());
          //long time = entry.getKey();
          //if ( prevTime != 0l && time - prevTime > 10l ) {
          //  try {
          //    Thread.sleep(time - prevTime);
          //  }
          //  catch ( InterruptedException ie ) {
          //    System.out.println("InterruptedException sending events to console: " + ie);
          //  }
          //}
          //prevTime = time;
          String msg = entry.getValue().genMessage();
          System.out.println(msg);
          pw.println(msg);
          pw.flush();
        }

	pw.close();
	s.close();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }

    private void loadEntityTree () throws IOException, ParseException {
      String strUrl = urlBeginText.getText() + "/controller/rest/applications?output=JSON";
      applications = (ADApplication[])fetchObj(strUrl, ADApplication[].class);
      for ( ADApplication app : applications ) {
        System.out.println("got app: " + app.name);
      //  strUrl = urlBeginText.getText() + "/controller/rest/applications/" + app.name + "/nodes?output=JSON";
      //  ADNode[] nodes = (ADNode[])fetchObj(strUrl, ADNode[].class);
      //  for ( ADNode node : nodes ) {
      //    node.fullPath = app.name + '|' + node.tierName + '|' + node.name;
      //    System.out.println("  tier " + node.tierName + ", node " + node.fullPath);
      //  }
      }
    }

    private Object fetchObj ( String strUrl, Class mapClass ) throws IOException, ParseException {
      System.out.println("fetching {" + strUrl + "}");
      URL url = new URL(strUrl);
      URLConnection urlConnection = url.openConnection();
      String authString = userText.getText() + ":" + passwordText.getText();
      String authStringEnc = new String(Base64.encodeBase64(authString.getBytes()));
      urlConnection.setRequestProperty("Authorization", "Basic " + authStringEnc);
      InputStreamReader reader = new InputStreamReader(urlConnection.getInputStream());
      ObjectMapper mapper = new ObjectMapper();
      Object obj = mapper.readValue(reader, mapClass);
      reader.close();
      return obj;
    }
  }
}
