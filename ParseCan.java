import java.io.*;
import java.util.*;

public class ParseCan {

	public static final double TIME_FACTOR = 100000d;

	public static void main ( String[] args ) {
		try {
			BufferedReader br = new BufferedReader(new FileReader("canbus.csv"));
			String line;
			for ( int i = 0; i < 38; i++ )
				line = br.readLine();

			long prevTime = 0;
			double prevFileTime = 0d;
			int nextId = 0;
			while ( (line = br.readLine()) != null ) {
				String split[] = line.split(",");
				String network = split[7];
				String arbid = split[9];
				String time = split[1];
				long outTime;
				if ( prevTime == 0 )
				       prevTime = System.currentTimeMillis() - 500000l;
				double fileTime = Double.parseDouble(time);
				if ( prevFileTime != 0 )
					outTime = prevTime + (long)Math.floor((fileTime - prevFileTime) * TIME_FACTOR);
				else
					outTime = prevTime;
				prevTime = outTime;
				prevFileTime = fileTime;
				String from = "canbus|canbus|" + network + '|' + arbid;
				String to = "all|all|all|all";	
				System.out.println(String.valueOf(nextId) + '\t' + outTime + '\t' + from + '\t' + to + "\t10|0");
				nextId++;
			}
			br.close();
		}
		catch ( Exception e ) {
			e.printStackTrace(System.out);
		}
	}
}
