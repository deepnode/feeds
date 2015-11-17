package com.threeshell;

import java.util.*;
import java.io.*;

import java.awt.EventQueue;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.JSeparator;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class Pro2beFrame extends JFrame {

  public JLabel statusLabel = new JLabel("Click SNIFF ALL to sniff");
  private JLabel addrLabel = new JLabel("Console address:");
  private JLabel portLabel = new JLabel("Console port:");
  private JLabel snortLabel = new JLabel("Snort command:");
  private JLabel snortInstruct = new JLabel("Must include '-A console'. Make blank if snort not installed.");
  public JButton monitorButt;
  public JButton pcapButt;
  public JButton advancedButt;
  public JPanel buttPanel;
  
  public Pro2beFrame () {
       setTitle("Sniffer Feed");
       setSize(400, 110);
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
                Pro2be.thePro2be.terminate();
                System.out.println("Closed");
                e.getWindow().dispose();
		System.exit(0);
            }
        });

      buttPanel = new JPanel();
      monitorButt = new JButton("SNIFF ALL");
      monitorButt.addActionListener(new MonitorAction());
      buttPanel.add(monitorButt);
      pcapButt = new JButton("Load PCAP");
      pcapButt.addActionListener(new PcapAction());
      buttPanel.add(pcapButt);
      advancedButt = new JButton("Advanced Options...");
      advancedButt.addActionListener(new AdvancedAction());
      buttPanel.add(advancedButt);
      add(buttPanel);
      add(statusLabel);
  }

  public void advanced () {
      add(new JSeparator());

      JPanel panel = new JPanel();
      panel.setSize(200, 80);
      panel.add(addrLabel);
      panel.add(Pro2be.thePro2be.addrField);
      add(panel);
      JPanel portPanel = new JPanel();
      portPanel.setSize(200, 80);
      portPanel.add(portLabel);
      portPanel.add(Pro2be.thePro2be.portField);
      add(portPanel);

      JPanel tcpdumpPanel = new JPanel();
      tcpdumpPanel.setSize(240, 80);
      tcpdumpPanel.add(Pro2be.thePro2be.tcpdumpField);
      JButton tcpButt = new JButton("RUN");
      tcpButt.addActionListener(new TcpdumpAction(false));
      tcpdumpPanel.add(tcpButt);
      JButton ingestButt = new JButton("INGEST");
      ingestButt.addActionListener(new TcpdumpAction(true));
      tcpdumpPanel.add(ingestButt);
      add(tcpdumpPanel);

      add(snortInstruct);
      JPanel snortPanel = new JPanel();
      snortPanel.setSize(200, 80);
      snortPanel.add(snortLabel);
      snortPanel.add(Pro2be.thePro2be.snortField);
      add(snortPanel);

      JPanel buttonPanel = new JPanel();
      JButton loadButt = new JButton("LOAD DN FILE");
      loadButt.addActionListener(new LoadAction());
      buttonPanel.add(loadButt);
      JButton syslogButt = new JButton("LOAD SYSLOG");
      syslogButt.addActionListener(new SyslogAction());
      buttonPanel.add(syslogButt);
      JButton writeButt = new JButton("WRITE DOMAINS");
      writeButt.addActionListener(new DomainAction());
      buttonPanel.add(writeButt);
      add(buttonPanel);
  }

  class MonitorAction implements ActionListener {

    public MonitorAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        if ( monitorButt.getText().startsWith("STOP") )
          Pro2be.thePro2be.cleanupSniffs();
        else
          Pro2be.thePro2be.setupSniff();
      }
      catch ( IOException ie ) {
        System.out.println("error starting/stopping sniffing: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class PcapAction implements ActionListener {

    public PcapAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(statusLabel);
        if ( returnVal == JFileChooser.APPROVE_OPTION )
          Pro2be.thePro2be.loadPcap(chooser.getSelectedFile().getAbsolutePath());
      }
      catch ( IOException ie ) {
        System.out.println("error loading pcap: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class AdvancedAction implements ActionListener {

    public AdvancedAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      setSize(540, 360);
      advanced();
      buttPanel.remove(advancedButt);
      revalidate();
    }
  }

  class TcpdumpAction implements ActionListener {

    private boolean doIngest = false;

    public TcpdumpAction ( boolean doIngest ) {
      this.doIngest = doIngest;
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        Pro2be.thePro2be.tcpdump(doIngest);
      }
      catch ( Exception ie ) {
        System.out.println("error starting command: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class LoadAction implements ActionListener {

    public LoadAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(statusLabel);
        if ( returnVal == JFileChooser.APPROVE_OPTION )
          Pro2be.thePro2be.loadFile(chooser.getSelectedFile().getAbsolutePath());
      }
      catch ( Exception ie ) {
        System.out.println("error loading file: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class SyslogAction implements ActionListener {

    public SyslogAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        JFileChooser chooser = new JFileChooser();
        int returnVal = chooser.showOpenDialog(statusLabel);
        if ( returnVal == JFileChooser.APPROVE_OPTION )
          Pro2be.thePro2be.loadSyslog(chooser.getSelectedFile().getAbsolutePath());
      }
      catch ( Exception ie ) {
        System.out.println("error loading syslog: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class DomainAction implements ActionListener {

    public DomainAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        Pro2be.thePro2be.writeDomains();
      }
      catch ( Exception ie ) {
        System.out.println("error writing domains: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }
}


