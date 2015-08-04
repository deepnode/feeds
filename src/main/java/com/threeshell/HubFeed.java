package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.zip.DeflaterOutputStream;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.nio.ByteBuffer;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JPasswordField;
import javax.swing.JButton;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class HubFeed extends JFrame implements Runnable {

  private BufferedReader inbr = null;
  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private boolean isWindows = false;
  private JLabel statusLabel = new JLabel("Click MONITOR to begin");
  private JLabel addrLabel = new JLabel("Console address:");
  private JTextField addrField = new JTextField("localhost", 20);
  private JLabel hubAddrLabel = new JLabel("Hub address:");
  private JTextField hubAddrField = new JTextField("", 20);
  private JLabel hubPortLabel = new JLabel("Hub port:");
  private JTextField hubPortField = new JTextField("", 10);
  private JLabel passLabel = new JLabel("Keystore pass:");
  private JPasswordField passField = new JPasswordField("", 16);
  public String overrideDir;
  public String configFname;

  public static void main ( String[] args ) {
    EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            HubFeed sniff = new HubFeed();
            sniff.setVisible(true);
            sniff.setup();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
    });
  }

  public HubFeed () {
       setTitle("Hub Feed");
       setSize(480, 240);
       setLocationRelativeTo(null);
       setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
       getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
  }

  public void setup () throws IOException, FileNotFoundException {
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

    JPanel panel = new JPanel();
    panel.setSize(120, 80);
    panel.add(addrLabel);
    panel.add(addrField);
    add(panel);
    JPanel hubAddrPanel = new JPanel();
    hubAddrPanel.setSize(120, 80);
    hubAddrPanel.add(hubAddrLabel);
    hubAddrPanel.add(hubAddrField);
    add(hubAddrPanel);
    JPanel hubPortPanel = new JPanel();
    hubPortPanel.setSize(120, 80);
    hubPortPanel.add(hubPortLabel);
    hubPortPanel.add(hubPortField);
    add(hubPortPanel);
    JPanel passPanel = new JPanel();
    passPanel.setSize(120, 80);
    passPanel.add(passLabel);
    passPanel.add(passField);
    add(passPanel);

    JButton butt = new JButton("MONITOR");
    butt.addActionListener(new MonitorAction(this));
    add(butt);

    add(statusLabel);

    overrideDir = System.getProperty("user.home") + File.separator + ".deepnode";
    createIfNotExist(overrideDir);
    overrideDir += File.separator;
    configFname = "hubfeed.properties";
    File configf = new File(overrideDir + configFname);
    if ( configf.exists() )
      readConfigFile(new FileReader(overrideDir + configFname));
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
    addrField.setText(props.getProperty("consoleaddr"));
    hubAddrField.setText(props.getProperty("hubaddr"));
    hubPortField.setText(props.getProperty("hubport"));
  }

  private void writeConfigFile () throws IOException {
    PrintWriter pw = new PrintWriter(new FileWriter(overrideDir + configFname));
    pw.println("consoleaddr=" + addrField.getText());
    pw.println("hubaddr=" + hubAddrField.getText());
    pw.println("hubport=" + hubPortField.getText());
    pw.close();
  }

  public void startMon () {
    try {
      writeConfigFile();
    }
    catch ( Exception e ) {
      System.out.println("error writing config file: " + e);
      e.printStackTrace(System.out);
    }

    Thread t = new Thread(this);
    t.start();
  }

  public void run () {
    while ( true ) {
      Socket s = null;
      try {
        statusLabel.setText("Looking for console...");
        s = new Socket(addrField.getText(), 4021);
        pw = new PrintWriter(new OutputStreamWriter(new DeflaterOutputStream(s.getOutputStream(), true)));
        br = new BufferedReader(new InputStreamReader(s.getInputStream()));
        pw.println("hub_feed");
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

  private void monitor () throws IOException, GeneralSecurityException {
    boolean isGood = true;
    long lastPing = 0;
    int port = Integer.parseInt(hubPortField.getText());
    Socket s = HubSock.getSocket(hubAddrField.getText(), port, passField.getText(), overrideDir);
    BufferedReader fbr = new BufferedReader(new InputStreamReader(s.getInputStream()));
    PrintWriter fpw = new PrintWriter(new OutputStreamWriter(s.getOutputStream()));
    String packStore = null;
    statusLabel.setText("Connected to hub feed!");
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.startsWith("pong") )
          isGood = false;
        else if ( line.startsWith("pong packdet ") )
          packStore = line.substring(13, line.length());
        lastPing = System.currentTimeMillis();
      }

      String line = fbr.readLine();
      if ( line != null ) {
        if ( line.equals("ping") ) {
          if ( packStore != null ) {
            fpw.println("pong packdet " + packStore);
            packStore = null;
          }
          else
            fpw.println("pong");
          fpw.flush();
        }
        else
          pw.println(line);
      }
    }
    fbr.close();
    s.close();
  }

  class MonitorAction implements ActionListener {

    private HubFeed feed;

    public MonitorAction ( HubFeed feed ) {
      this.feed = feed;
    }

    public void actionPerformed ( ActionEvent e ) {
      feed.startMon();
    }
  }
}
