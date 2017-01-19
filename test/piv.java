import com.licel.jcardsim.base.Simulator;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.cryptonit.CryptonitApplet;

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

        arg = new byte[]{
            (byte) 0x7C, (byte) 0x14,
            (byte) 0x80, (byte) 0x08,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x81, (byte) 0x08,
            (byte) 0x2B, (byte) 0x65, (byte) 0x4B, (byte) 0x22, (byte) 0xB2, (byte) 0x2D, (byte) 0x99, (byte) 0x7F
        };
        SecretKey key = new SecretKeySpec(new byte[]{
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        }, "DESede");
        try {
            Cipher cipher = Cipher.getInstance("DESede/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            cipher.doFinal(response.getData(), 4, 8, arg, 4);
        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

        System.out.println("Management key authentication (part 2)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x87, 0x03, 0x9B, arg)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));
    }
}
