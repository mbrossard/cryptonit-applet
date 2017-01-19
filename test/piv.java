import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;

/**
 * @author Mathias Brossard
 */

class piv {
    public static void main(String[] args) {
        Simulator simulator = new Simulator();
        byte[] arg;
        byte[] appletAIDBytes = new byte[]{
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03,
            (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x10,
            (byte) 0x00
        };
        short sw, le;
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        simulator.installApplet(appletAID, CryptonitApplet.class);
    }
}
