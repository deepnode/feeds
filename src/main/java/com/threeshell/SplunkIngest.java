package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.*;
import java.net.UnknownHostException;
import java.util.zip.DeflaterOutputStream;
import java.text.*;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.codehaus.jackson.map.ObjectMapper;

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
import com.splunk.*;

public class SplunkIngest extends JFrame {

  private BufferedReader inbr = null;
  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private HashMap<String, String> domainMap = new HashMap<String, String>();
  private boolean isWindows = false;
  private JLabel configLabel = new JLabel("looking for config file");
  //private JLabel fieldLabel = new JLabel("looking for field file");
  private JTextArea searchText = new JTextArea();
  private JButton searchButton = new JButton("search");
  private JPasswordField passwordText = new JPasswordField(30);
  private JTextField beginText = new JTextField(20);
  private JTextField endText = new JTextField(20);

  private long nextMsgId = 1l;
  private String consoleAddr = null;
  private String splunkHost = null;
  private String splunkUser = null;
  private int splunkPort = 8089;
  public SpelunkerFieldset[] mappings = null;
  public HashMap<String, SpelunkerFieldset> mappingMap = new HashMap<String, SpelunkerFieldset>();
  public static SplunkIngest splunkIngest = null;

  public static void main ( String[] args ) {
    EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            splunkIngest = new SplunkIngest();
            splunkIngest.setVisible(true);
            splunkIngest.setup();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
    });
  }

  public SplunkIngest () {
       setTitle("Deep Node SPeLUNKer");
       setSize(560, 200);
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

    add(configLabel);
    JPanel passPanel = new JPanel();
    passPanel.setSize(300, 100);
    passPanel.add(new JLabel("splunk password"));
    passPanel.add(passwordText);
    add(passPanel);
    add(searchText);
    searchText.setText("search * | sort +_time");
    JPanel timePanel = new JPanel();
    timePanel.setSize(500, 100);
    timePanel.add(new JLabel("begin"));
    timePanel.add(beginText);
    timePanel.add(new JLabel("end"));
    timePanel.add(endText);
    add(timePanel);
    add(searchButton);
    searchButton.addActionListener(new ActionListener() {
      public void actionPerformed(ActionEvent e) {
        doSearch();
      }
    });
    //add(fieldLabel);

    String overrideDir = System.getProperty("user.home") + File.separator + ".deepnode" + File.separator;
    String configFname = "splunk_ingest.properties";
    File configf = new File(overrideDir + configFname);
    if ( configf.exists() )
      readConfigFile(new FileReader(overrideDir + configFname));
    else
      configLabel.setText("need config: " + overrideDir + configFname);

    String mapFname = "spelunker_map.json";
    File mapf = new File(overrideDir + mapFname);
    if ( mapf.exists() )
      readMapFile(new FileReader(overrideDir + mapFname));
    else
      configLabel.setText(configLabel.getText() + ", need map: " + overrideDir + mapFname);

    //String fieldFname = "splunk_fields.txt";
    //File fieldf = new File(overrideDir + fieldFname);
    //if ( fieldf.exists() )
    //  fieldLabel.setText("fields file parsed");
    //else
    //  fieldLabel.setText("need fields: " + overrideDir + fieldFname);
  }

  public void doSearch () {
    SearchRun sr = new SearchRun();
    Thread t = new Thread(sr);
    t.start();
  }

  private void readConfigFile ( Reader r ) throws IOException {
    Properties props = new Properties();
    props.load(r);
    r.close();
    consoleAddr = props.getProperty("consoleAddr");
    splunkHost = props.getProperty("splunkHost");
    splunkUser = props.getProperty("splunkUser");
    String splunkPortStr = props.getProperty("splunkPort");
    if ( splunkPortStr != null )
      splunkPort = Integer.parseInt(splunkPortStr);
    configLabel.setText("config file parsed");
  }

  private void readMapFile ( Reader r ) throws JsonParseException, JsonMappingException, IOException {
    ObjectMapper mapper = new ObjectMapper();
    mappings = mapper.readValue(r, SpelunkerFieldset[].class);
    for ( SpelunkerFieldset sfs : mappings )
      mappingMap.put(sfs.source, sfs);
    configLabel.setText(configLabel.getText() + ", map read");
  }

  public String getLocation ( String addr ) {
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

  public String lookupDomain ( String addr ) {
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

    public final int BUFMAX = 4096;
    private char[] buf = new char[BUFMAX];
    private HashMap<String, Integer> extractKeys = new HashMap<String, Integer>();
    private PrintWriter pw = null;
    private SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.S zzz");

    public void run () {
      try {
        ServiceArgs loginArgs = new ServiceArgs();
        loginArgs.setUsername(splunkUser);
        loginArgs.setPassword(passwordText.getText());
        loginArgs.setHost(splunkHost);
        loginArgs.setPort(splunkPort);

        Service service = Service.connect(loginArgs);

	JobExportArgs exportArgs = new JobExportArgs();
        if ( beginText.getText() != null )
	  exportArgs.setEarliestTime(beginText.getText());
        if ( endText.getText() != null )
	  exportArgs.setLatestTime(endText.getText());
	exportArgs.setSearchMode(JobExportArgs.SearchMode.NORMAL);
	exportArgs.setOutputMode(JobExportArgs.OutputMode.JSON);
        //exportArgs.setOutputTimeFormat("YYYY-MM-DDThh:mm:ss.sTZD");

	InputStream exportSearch = service.export(searchText.getText(), exportArgs);
	ResultsReaderJson resultsReader = new ResultsReaderJson(exportSearch);

        Socket s = new Socket(consoleAddr, 4021);
        pw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(s.getOutputStream(), true)));
        pw.println("splunk_ingest");
        pw.flush();

        Event event;
        while ( (event = resultsReader.getNextEvent()) != null ) {
          parseEvent(event);
        }
        resultsReader.close();
	pw.close();
	s.close();
      }
      catch ( Exception e ) {
        e.printStackTrace(System.out);
      }
    }

    private void parseEvent ( Event event ) throws ParseException {
      String time = event.get("_time");
      String raw = event.get("_raw");
      String sourceType = event.get("sourcetype");
      SpelunkerFieldset sfs = mappingMap.get(sourceType);
      if ( sfs == null ) {
        System.out.println("no fieldset for sourcetype " + sourceType);
        return;
      }

      int srcEnd = raw.length();
      if ( srcEnd > BUFMAX )
        srcEnd = BUFMAX;
      raw.getChars(0, srcEnd, buf, 0);

      HashMap<String, String> eventAttrs = new HashMap<String, String>();
      boolean gotEquals = false;
      boolean inQuotes = false;
      StringBuilder sbKey = new StringBuilder();
      StringBuilder sbVal = new StringBuilder();
      for ( int i = 0; i < srcEnd; i++ ) {
        char c = buf[i];
        if ( !inQuotes && (c == ' ' || c == '\r' || c == '\n' || c == '\t') ) {
          if ( sbKey.length() > 0 && sbVal.length() > 0 )
            eventAttrs.put(sbKey.toString(), sbVal.toString());
          sbKey = new StringBuilder();
          sbVal = new StringBuilder();
          gotEquals = false;
        }
        else if ( !inQuotes && !gotEquals && c == '=' )
          gotEquals = true;
        else if ( c == '"' )
          inQuotes = !inQuotes;
        else if ( gotEquals )
          sbVal.append(c);
        else
          sbKey.append(c);
      }

      sfs.process(eventAttrs);
      sendEvent(time, sfs);
    } 

    private void sendEvent ( String time, SpelunkerFieldset sfs ) throws ParseException {
      String part1 = time.substring(0, 23);
      String[] part2 = time.substring(24, time.length()).split(" ");
      String tz = "";
      for ( String s : part2 )
        tz += s.substring(0, 1);
      java.util.Date dt = sdf.parse(part1 + " " + tz);

      StringBuilder sb = new StringBuilder();
      sb.append(String.valueOf(nextMsgId));
      nextMsgId++;
      sb.append('\t');

      sb.append(String.valueOf(dt.getTime()));
      sb.append('\t');

      sb.append(sfs.resultFromAddr);
      sb.append('\t');
      sb.append(sfs.resultToAddr);

      sb.append('\t');
      String meas = sfs.resultMeasure;
      if ( Integer.parseInt(meas) <= 0 )
        meas = "1";
      sb.append(meas);
      sb.append('|');
      sb.append("0");

      String str = sb.toString();
      pw.println(str);
    }
  }
}
