import com.licel.jcardsim.base.Simulator;
import org.cryptonit.CryptonitApplet;
import javacard.framework.AID;

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
    }
}
