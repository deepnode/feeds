package com.threeshell;

import java.io.*;

public class Purger implements Runnable {

  public static final long WAIT_INTERVAL = 10000l;
  private Pro2be theProbe;

  public Purger ( Pro2be thePro2be ) {
    this.theProbe = thePro2be;
  }

  public void run () {
    long prevTs = 0l;
    while ( true ) {
      try {
        if ( System.currentTimeMillis() > prevTs + WAIT_INTERVAL ) {
          prevTs = System.currentTimeMillis();
          purgeIfNecessary();
        }
        else {
          Thread.sleep(500);
        }
      }
      catch ( Exception e ) {
        System.out.println("Purger error: " + e);
        e.printStackTrace(System.out);
      }
    }
  }

  private void purgeIfNecessary () throws IOException {
    String mainPath = theProbe.storagePath;
    if ( !mainPath.endsWith(File.separator) )
      mainPath += File.separator;

    File mainDir = new File(mainPath);
    if ( mainDir.getFreeSpace() > theProbe.minFreeSpace )
      return;

    String[] subdirList = mainDir.list();
    if ( subdirList == null || subdirList.length < 1 )
      return;

    File subDir = new File(mainPath + subdirList[0]);
    String[] fileList = subDir.list();
    if ( fileList == null || fileList.length < 1 ) {
      System.out.println("removing subdir " + subDir);
      subDir.delete();
    }
    else {
      File firstFile = new File(mainPath + subdirList[0] + File.separator +
                       fileList[0]);
      System.out.println("deleting file " + firstFile);
      firstFile.delete();
    }
  }
}
