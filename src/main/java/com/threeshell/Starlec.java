package com.threeshell;

import java.util.*;

public class Starlec {

  public int tick = 0;
  public int resetCount = 0;
  private LinkedList<Lec> prevActives = null;
  public LinkedList<Lec> actives = null;
  public TreeMap<String, Lec> allLecs = new TreeMap<String, Lec>();

  public void consume ( int c ) {
    String key = "" + (char)c;
    System.out.print(key);
    Lec l = allLecs.get(key);
    if ( l == null ) {
      l = new Lec(key);
      allLecs.put(key, l);
    }
    actives = new LinkedList<Lec>();
    l.stim(null);

    if ( prevActives != null ) {
      for ( Lec prevActive : prevActives )
        prevActive.spawn(l);
    }
    prevActives = actives;
    tick++;
  }

  public void reset () {
    tick = 0;
    resetCount++;
    for ( Lec l : allLecs.values() )
      l.reset();
  }

  class Lec {

    public int activateCount = 0;
    public int pathLevel = 0;
    public int lastTick = -2;
    public Lec[] path = null;
    private String key = null;
    public LinkedList<Lec> subscribers = new LinkedList<Lec>();

    public Lec ( Lec[] path ) {
      this.path = path;
    }

    public Lec ( String key ) {
      this.key = key;
    }

    public String getKey () {
      if ( key == null ) {
        key = "";
        for ( Lec l : path )
          key += l.getKey();
      }
      return key;
    }

    public void stim ( Lec stimulator ) {
      if ( path == null ) {
        activate();
        return;
      }

      if ( stimulator != path[pathLevel] ||
           (pathLevel > 0 && tick - lastTick > 1) ) {
        reset();
        return;
      }

      pathLevel++;
      lastTick = tick;

      if ( pathLevel == path.length )
        activate();
    }

    public void activate () {
      activateCount++;
      actives.add(this);

      Iterator<Lec> iter = subscribers.iterator();
      while ( iter.hasNext() ) {
        Lec l = iter.next();
        //if ( l.isDead() )
        //  iter.remove(l);
        //else
        l.stim(this);
      }

      reset();
    }

    public void reset () {
      pathLevel = 0;
      lastTick = -2;
    }

    public void spawn ( Lec l ) {
      Lec[] newPath = new Lec[2];
      newPath[0] = this;
      newPath[1] = l;
      Lec baby = new Lec(newPath);
      allLecs.put(baby.getKey(), baby);
      subscribers.add(baby);
      l.subscribers.add(baby);
      //System.out.println(baby.getKey());
    }
  }
}

