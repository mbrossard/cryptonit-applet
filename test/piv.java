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
        System.out.println("Select Applet");
        ResponseAPDU response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new byte[]{
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08
        })).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        System.out.println("Management key authentication (part 1)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x87, 0x03, 0x9B,  new byte []{
            (byte) 0x7C, (byte) 0x02, (byte) 0x80, (byte) 0x00
        })).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));
    }
}
