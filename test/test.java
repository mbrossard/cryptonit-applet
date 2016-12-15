import com.licel.jcardsim.base.Simulator;
import org.cryptonit.CryptonitApplet;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

class test {
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
    }
}
