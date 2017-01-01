import com.licel.jcardsim.base.Simulator;
import org.cryptonit.CryptonitApplet;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * @author Mathias Brossard
 */

class test {
    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if((i != 0) && ((i % 32) == 0)) {
                sb.append("\n");
            }
            sb.append(String.format("%02X ", bytes[i]));
        }
        return sb.toString();
    }

    public static void main(String[] args) {
        Simulator simulator = new Simulator();

        byte[] appletAIDBytes = new byte[]{
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03,
            (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x10,
            (byte) 0x00
        };
        AID appletAID = new AID(appletAIDBytes, (short) 0, (byte) appletAIDBytes.length);

        simulator.installApplet(appletAID, CryptonitApplet.class);
        simulator.selectApplet(appletAID);

        System.out.println("Select Applet");
        ResponseAPDU response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xA4, 0x04, 0x00)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        System.out.println("Get 0x7E file");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, new byte []{
            (byte) 0x5C, (byte) 0x01, (byte) 0x7E
        }, 0x100)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        System.out.println("Verify PIN");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x20, 0x00, 0x80, new byte []{
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        })).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));
        
        System.out.println("Generate P-256 EC key (9D)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x47, 0x00, 0x9D, new byte[]{
            (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x11
        })).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        System.out.println("Generate 2048 bit RSA key (9A)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x47, 0x00, 0x9A, new byte []{
                (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x07
        }, 0x200)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        System.out.println("Read 0x5FC105 file");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, new byte []{
                (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05
        })).getBytes()));
        System.out.println(response.toString());

        System.out.println("Write to 0x5FC105 file");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xDB, 0x3F, 0xFF, new byte []{
                (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05,
                (byte) 0x53, (byte) 0x04, (byte) 0x11, (byte) 0x22, (byte) 0x33, (byte) 0x44,
        })).getBytes()));
        System.out.println(response.toString());
    }
}
