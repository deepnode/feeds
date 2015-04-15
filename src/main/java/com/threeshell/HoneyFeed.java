package com.threeshell;

import java.util.*;
import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
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
import javax.swing.JButton;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class HoneyFeed extends JFrame implements Runnable {

  private BufferedReader inbr = null;
  private int nextInd = 0;
  private PrintWriter pw;
  private BufferedReader br;
  private boolean isWindows = false;
  private JLabel statusLabel = new JLabel("Looking for console...");
  private JLabel addrLabel = new JLabel("Console address:");
  private JTextField addrField = new JTextField("localhost", 20);

  public static void main ( String[] args ) {
    EventQueue.invokeLater(new Runnable() {
        @Override
        public void run() {
	  try {
            HoneyFeed sniff = new HoneyFeed();
            sniff.setVisible(true);
            sniff.setup();
          }
	  catch ( Exception e ) {
            e.printStackTrace(System.out);
	  }
        }
    });
  }

  public HoneyFeed () {
       setTitle("Honeypot Feed");
       setSize(320, 120);
       setLocationRelativeTo(null);
       setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
       getContentPane().setLayout(new BoxLayout(getContentPane(), BoxLayout.Y_AXIS));
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

    String os = System.getProperty("os.name").toLowerCase();
    if ( os.indexOf("win") > -1 )
      isWindows = true;

    Thread t = new Thread(this);
    t.start();

    JPanel panel = new JPanel();
    panel.setSize(120, 80);
    panel.add(addrLabel);
    panel.add(addrField);
    add(panel);
    add(statusLabel);
  }

  public void run () {
    while ( true ) {
      Socket s = null;
      try {
        s = new Socket(addrField.getText(), 4021);
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

  private void monitor () throws IOException {
    boolean isGood = true;
    long lastPing = 0;
    Socket s = new Socket("deepnode.us", 4023);
    BufferedReader fbr = new BufferedReader(new InputStreamReader(s.getInputStream()));
    statusLabel.setText("Connected to honeypot feed!");
    while ( pw != null && isGood ) {
      if ( lastPing == 0 || System.currentTimeMillis() - lastPing > 5000 ) {
        pw.println("ping");
        pw.flush();
        String line = br.readLine();
        if ( line == null || !line.equals("pong") )
          isGood = false;
        lastPing = System.currentTimeMillis();
      }

      String line = fbr.readLine();
      if ( line != null ) {
        pw.println(line);
	pw.flush();
      }
    }
    statusLabel.setText("Looking for console...");
    fbr.close();
    s.close();
  }
}
