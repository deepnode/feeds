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
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.WindowConstants;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;

public class Pro2beFrame extends JFrame {

  public JLabel statusLabel = new JLabel("Click MONITOR ALL to sniff");
  private JLabel addrLabel = new JLabel("Console address:");
  private JLabel portLabel = new JLabel("Console port:");
  private JLabel tcpdumpLabel = new JLabel("Cmd:");
  private JLabel snortLabel = new JLabel("Snort command:");
  private JLabel snortInstruct = new JLabel("Must include '-A console'. Make blank if snort not installed.");
  
  public Pro2beFrame () {
       setTitle("Sniffer Feed");
       setSize(480, 280);
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
      tcpdumpPanel.setSize(200, 80);
      tcpdumpPanel.add(tcpdumpLabel);
      tcpdumpPanel.add(Pro2be.thePro2be.tcpdumpField);
      JButton tcpButt = new JButton("RUN");
      tcpButt.addActionListener(new TcpdumpAction());
      tcpdumpPanel.add(tcpButt);
      add(tcpdumpPanel);

      add(snortInstruct);
      JPanel snortPanel = new JPanel();
      snortPanel.setSize(200, 80);
      snortPanel.add(snortLabel);
      snortPanel.add(Pro2be.thePro2be.snortField);
      add(snortPanel);

      JPanel buttonPanel = new JPanel();
      JButton butt = new JButton("MONITOR ALL");
      butt.addActionListener(new MonitorAction());
      buttonPanel.add(butt);
      JButton loadButt = new JButton("LOAD FILE");
      loadButt.addActionListener(new LoadAction());
      buttonPanel.add(loadButt);
      add(buttonPanel);

      add(statusLabel);
  }

  class MonitorAction implements ActionListener {

    public MonitorAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        Pro2be.thePro2be.setupSniff();
      }
      catch ( IOException ie ) {
        System.out.println("error starting monitoring: " + ie);
        ie.printStackTrace(System.out);
      }
    }
  }

  class TcpdumpAction implements ActionListener {

    public TcpdumpAction () {
    }

    public void actionPerformed ( ActionEvent e ) {
      try {
        Pro2be.thePro2be.tcpdump();
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
}


