import com.licel.jcardsim.base.Simulator;
import org.cryptonit.CryptonitApplet;
import javacard.framework.AID;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
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

        byte [] arg;
        byte [] tmp = new byte[768 + 9];
        Util.arrayCopy(new byte []{
                (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05,
                (byte) 0x53, (byte) 0x82, (byte) 0x03, (byte) 0x00
        }, (byte)0, tmp, (byte)0, (byte)9);
        for(int i = 0; i < 768; i++) {
            tmp[i + 9] = (byte)(i % 10);
        }
        System.out.println("Write to 0x5FC105 file (large)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xDB, 0x3F, 0xFF, tmp, 0x400)).getBytes()));
        System.out.println(response.toString());

        arg = Arrays.copyOfRange(tmp, 0, 255);
        System.out.println("Write to 0x5FC105 file (large, chaining 1)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x10, 0xDB, 0x3F, 0xFF, arg)).getBytes()));
        System.out.println(response.toString());
        arg = Arrays.copyOfRange(tmp, 256, 511);
        System.out.println("Write to 0x5FC105 file (large, chaining 2)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x10, 0xDB, 0x3F, 0xFF, arg)).getBytes()));
        System.out.println(response.toString());
        arg = Arrays.copyOfRange(tmp, 512, 767);
        System.out.println("Write to 0x5FC105 file (large, chaining 3)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x10, 0xDB, 0x3F, 0xFF, arg)).getBytes()));
        System.out.println(response.toString());
        arg = Arrays.copyOfRange(tmp, 768, 776);
        System.out.println("Write to 0x5FC105 file (large, chaining 4)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x10, 0xDB, 0x3F, 0xFF, arg)).getBytes()));
        System.out.println(response.toString());

        System.out.println("Read 0x5FC105 file (large)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, new byte[]{
            (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05
        })).getBytes()));
        System.out.println(response.toString());

        short sw, le;
        while (((sw = (short) response.getSW()) & 0xFF00) == 0x6100) {
            le = (short) (sw & 0xFF);
            System.out.println("Call GET RESPONSE");
            response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xC0, 0x00, 0x00, new byte[]{}, le)).getBytes()));
            System.out.println(response.toString());
        }
        
        /* RSA signature request */
        byte [] sig_request = new byte []{
            (byte) 0x7C, (byte) 0x82, (byte) 0x01, (byte) 0x06,
            (byte) 0x82, (byte) 0x00,
            (byte) 0x81, (byte) 0x82, (byte) 0x01, (byte) 0x00,
            (byte) 0x00, (byte) 0x01, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 01
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 02
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 03
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 04
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 05
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 06
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 07
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 08
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 09
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 10
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 11
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 12
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 13
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 14
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 15
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 16
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 17
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 18
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 19
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 20
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 21
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 22
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 23
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 24
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 25
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 26
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, // 27
            (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x00, (byte) 0x9D, (byte) 0xF4, (byte) 0x6E, (byte) 0x09, // 28
            (byte) 0xE7, (byte) 0xD6, (byte) 0x19, (byte) 0x18, (byte) 0x53, (byte) 0x1E, (byte) 0x6E, (byte) 0x1C, // 29
            (byte) 0x66, (byte) 0x87, (byte) 0xC4, (byte) 0x3E, (byte) 0xCF, (byte) 0xFF, (byte) 0x7D, (byte) 0x53, // 30
            (byte) 0x47, (byte) 0xBD, (byte) 0x2E, (byte) 0x93, (byte) 0x19, (byte) 0x94, (byte) 0x53, (byte) 0x76, // 31
            (byte) 0xFE, (byte) 0xA7, (byte) 0x91, (byte) 0x72, (byte) 0x14, (byte) 0x18, (byte) 0xBC, (byte) 0xA7  // 32
        };
        System.out.println("RSA signature file (extended length APDUs)");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x87, 0x07, 0x9A, sig_request, 0x200)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));
        
        System.out.println("RSA signature file (chained APDUs) first command");
        arg = Arrays.copyOfRange(sig_request, 0, 255);
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x10, 0x87, 0x07, 0x9A, arg)).getBytes()));
        System.out.println(response.toString());

        System.out.println("RSA signature file (chained APDUs) second command");
        arg =  Arrays.copyOfRange(sig_request, 255, sig_request.length);
        System.out.println(arg.length);
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0x87, 0x07, 0x9A, arg)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));

        sw = (short) response.getSW();
        le = (short) (sw & 0xFF);
        System.out.println("Call GET RESPONSE");
        response = new ResponseAPDU(simulator.transmitCommand((new CommandAPDU(0x00, 0xC0, 0x00, 0x00, new byte []{
        }, le)).getBytes()));
        System.out.println(response.toString());
        System.out.println(toHex(response.getData()));
    }
}
