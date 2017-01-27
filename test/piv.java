import com.licel.jcardsim.base.Simulator;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Date;
import javacard.framework.AID;
import javacard.framework.Util;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OutputStream;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V1TBSCertificateGenerator;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.cryptonit.CryptonitApplet;

/**
 * @author Mathias Brossard
 */
class piv {
    private static String toHex(String prefix, byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        sb.append(prefix);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02x ", bytes[i]));
        }
        return sb.toString();
    }

    private static ResponseAPDU sendAPDU(Simulator simulator, CommandAPDU command) {
        ResponseAPDU response;
        System.out.println(toHex(" > ", command.getBytes()));
        response = new ResponseAPDU(simulator.transmitCommand(command.getBytes()));
        System.out.println(toHex(" < ", response.getData())
                + String.format("[sw=%04X l=%d]", response.getSW(), response.getData().length));
        return response;
    }

    public static void main(String[] args) {
        ResponseAPDU response;
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
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xA4, 0x04, 0x00, new byte[]{
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08
        }));

        System.out.println("Management key authentication (part 1)");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x87, 0x03, 0x9B, new byte[]{
            (byte) 0x7C, (byte) 0x02, (byte) 0x80, (byte) 0x00
        }));

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
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x87, 0x03, 0x9B, arg));
        System.out.println("Generate RSA key (9A)");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x47, 0x00, 0x9A, new byte[]{
            (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x07
        }));
        arg = response.getData();
        if (arg.length < 9 || arg[7] != 0x1 || arg[8] != 0x0) {
            System.err.println("Error modulus");
            return;
        }

        byte[] n = new byte[257];
        byte[] e = new byte[3];
        short s = (short) (arg.length - 9);
        Util.arrayCopy(arg, (short) 9, n, (short) 1, s);

        sw = (short) response.getSW();
        le = (short) (sw & 0xFF);
        System.out.println("Call GET RESPONSE");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xC0, 0x00, 0x00, new byte[]{}, le));

        arg = response.getData();
        if(arg.length < (256 - s)) {
            System.err.println("Error remaining modulus");
            return;            
        }
        Util.arrayCopy(arg, (short) 0, n, (short) (s + 1), (short) (256 - s));

        s = (short) (256 - s);
        if (arg[s] != (byte) 0x82 || arg[s + 1] != (byte) 0x3) {
            System.err.println("Error exponent");
            return;
        }
        Util.arrayCopy(arg, (short) (s + 2), e, (short) 0, (short) 3);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        TBSCertificate tbs;
        try {
            RSAPublicKey rsa_pub = new RSAPublicKey(new BigInteger(n), new BigInteger(e));
            AlgorithmIdentifier palgo = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
            V1TBSCertificateGenerator tbsGen = new V1TBSCertificateGenerator();
            tbsGen.setSerialNumber(new ASN1Integer(0x1));
            tbsGen.setStartDate(new Time(new Date(100, 01, 01, 00, 00, 00)));
            tbsGen.setEndDate(new Time(new Date(130, 12, 31, 23, 59, 59)));
            tbsGen.setIssuer(new X500Name("CN=Cryptonit"));
            tbsGen.setSubject(new X500Name("CN=Cryptonit"));
            tbsGen.setSignature(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
            tbsGen.setSubjectPublicKeyInfo(new SubjectPublicKeyInfo(palgo, rsa_pub));
            tbs = tbsGen.generateTBSCertificate();

            ASN1OutputStream aOut = new ASN1OutputStream(bOut);
            aOut.writeObject(tbs);
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
            return;
        }

        byte[] digest = null;
        try {
            MessageDigest md;
            md = MessageDigest.getInstance("SHA-256");
            md.update(bOut.toByteArray());
            digest = md.digest();
        } catch (Exception ex) {
            ex.printStackTrace(System.err);
            return;
        }
        System.out.println("Verify PIN");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x20, 0x00, 0x80, new byte[]{
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
        }));

        /* RSA signature request */
        byte[] sig_request = new byte[266], sig_prefix = new byte[]{
            (byte) 0x7C, (byte) 0x82, (byte) 0x01, (byte) 0x06,
            (byte) 0x82, (byte) 0x00,
            (byte) 0x81, (byte) 0x82, (byte) 0x01, (byte) 0x00,
            (byte) 0x00, (byte) 0x01
        };

        Util.arrayFillNonAtomic(sig_request, (short) 0, (short) sig_request.length, (byte) 0xFF);
        Util.arrayCopy(sig_prefix, (short) 0, sig_request, (short) 0, (short) sig_prefix.length);
        sig_request[sig_request.length - digest.length - 1] = 0x0;
        Util.arrayCopy(digest, (short) 0, sig_request, (short) (sig_request.length - digest.length), (short) (digest.length));

        System.out.println("RSA signature file (chained APDUs) first command");
        arg = Arrays.copyOfRange(sig_request, 0, 255);
        response = sendAPDU(simulator, new CommandAPDU(0x10, 0x87, 0x07, 0x9A, arg));

        System.out.println("RSA signature file (chained APDUs) second command");
        arg = Arrays.copyOfRange(sig_request, 255, sig_request.length);
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x87, 0x07, 0x9A, arg));

        arg = response.getData();
        byte[] sig = new byte[256];
        if (arg.length > 8 && arg[6] == 0x1 && arg[7] == 0x0) {
            s = (short) (arg.length - 8);
            Util.arrayCopy(arg, (short) 8, sig, (short) 0, s);
        } else {
            System.err.println("Error in signature");
            return;
        }

        sw = (short) response.getSW();
        le = (short) (sw & 0xFF);
        System.out.println("Call GET RESPONSE");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xC0, 0x00, 0x00, new byte[]{}, le));

        arg = response.getData();
        Util.arrayCopy(arg, (short) 0, sig, s, (short) (256 - s));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE));
        v.add(new DERBitString(sig));

        byte [] crt = null;
        try {
            Certificate c = Certificate.getInstance(new DERSequence(v));
            crt = c.getEncoded();
        } catch (Exception ex) {
            ex.printStackTrace(System.out);
        }

        byte[] prefix = new byte[]{
            (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05,
            (byte) 0x53, (byte) 0x82 
        }, postfix = new byte[]{
            (byte) 0x71, (byte) 0x01, (byte) 0x00, (byte) 0xFE, (byte) 0x00
        };

        short len = (short) (prefix.length + crt.length + 6 + postfix.length);
        byte[] buffer = new byte[len];

        Util.arrayCopy(prefix, (short) 0, buffer, (short) 0, (short) prefix.length);
        int off = prefix.length;
        buffer[off++] = (byte) (((crt.length + postfix.length + 4) >> 8) & 0xFF);
        buffer[off++] = (byte) ((crt.length + postfix.length + 4) & 0xFF);

        buffer[off++] = (byte) 0x70;
        buffer[off++] = (byte) 0x82;
        buffer[off++] = (byte) ((crt.length >> 8) & 0xFF);
        buffer[off++] = (byte) (crt.length & 0xFF);
        Util.arrayCopy(crt, (short) 0, buffer, (short) off, (short) crt.length);
        off += crt.length;
        Util.arrayCopy(postfix, (short) 0, buffer, (short) off, (short) postfix.length);

        int i = 1, left = buffer.length, sent = 0;
        while(left > 0) {
            System.out.println(String.format("Uploading certificate part %d", i++));
            int cla = (left <= 255) ? 0x00 : 0x10;
            int sending = (left <= 255) ? left : 255;
            arg = Arrays.copyOfRange(buffer, sent, sent + sending);
            response = sendAPDU(simulator, new CommandAPDU(cla, 0xDB, 0x3F, 0xFF, arg));
            sent += sending;
            left -= sending;
        }

        System.out.println("Read 0x5FC105 file (large)");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xCB, 0x3F, 0xFF, new byte[]{
            (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x05
        }));

        while (((sw = (short) response.getSW()) & 0xFF00) == 0x6100) {
            le = (short) (sw & 0xFF);
            System.out.println("Call GET RESPONSE");
            response = sendAPDU(simulator, new CommandAPDU(0x00, 0xC0, 0x00, 0x00, new byte[]{}, le));
        }

        System.out.println("Generate EC P256 key (9C)");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0x47, 0x00, 0x9C, new byte[]{
            (byte) 0xAC, (byte) 0x03, (byte) 0x80, (byte) 0x01, (byte) 0x11
        }));
        arg = response.getData();
        if (arg.length < 9 || arg[3] != (byte) 0x86 || arg[4] != 0x41) {
            System.err.println("Error EC Public key");
            return;
        }

        prefix = new byte[]{
            (byte) 0x30, (byte) 0x59, (byte) 0x30, (byte) 0x13, (byte) 0x06,
            (byte) 0x07, (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE,
            (byte) 0x3D, (byte) 0x02, (byte) 0x01, (byte) 0x06, (byte) 0x08,
            (byte) 0x2A, (byte) 0x86, (byte) 0x48, (byte) 0xCE, (byte) 0x3D,
            (byte) 0x03, (byte) 0x01, (byte) 0x07, (byte) 0x03, (byte) 0x42,
            (byte) 0x00
        };
        buffer = new byte[prefix.length + 65];
        Util.arrayCopy(prefix, (short) 0, buffer, (short) 0, (short) prefix.length);
        Util.arrayCopy(arg, (short) 5, buffer, (short) prefix.length, (short) 65);
        System.out.println("Set Card Capabilities Container");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xDB, 0x3F, 0xFF, new byte[]{
            (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x07,
            (byte) 0x53, (byte) 0x33, (byte) 0xF0, (byte) 0x15, (byte) 0xA0,
            (byte) 0x00, (byte) 0x00, (byte) 0x01, (byte) 0x16, (byte) 0xFF,
            (byte) 0x02, (byte) 0x30, (byte) 0x1D, (byte) 0x9C, (byte) 0x5D,
            (byte) 0xB7, (byte) 0xA3, (byte) 0x87, (byte) 0xF1, (byte) 0xBE,
            (byte) 0x25, (byte) 0x1F, (byte) 0xB9, (byte) 0xFB, (byte) 0x1A,
            (byte) 0xF1, (byte) 0x01, (byte) 0x21, (byte) 0xF2, (byte) 0x01,
            (byte) 0x21, (byte) 0xF3, (byte) 0x00, (byte) 0xF4, (byte) 0x01,
            (byte) 0x00, (byte) 0xF5, (byte) 0x01, (byte) 0x10, (byte) 0xF6,
            (byte) 0x00, (byte) 0xF7, (byte) 0x00, (byte) 0xFA, (byte) 0x00,
            (byte) 0xFB, (byte) 0x00, (byte) 0xFC, (byte) 0x00, (byte) 0xFD,
            (byte) 0x00, (byte) 0xFE, (byte) 0x00
        }));                

        System.out.println("Set CHUID");
        response = sendAPDU(simulator, new CommandAPDU(0x00, 0xDB, 0x3F, 0xFF, new byte[]{
            (byte) 0x5C, (byte) 0x03, (byte) 0x5F, (byte) 0xC1, (byte) 0x02,
            (byte) 0x53, (byte) 0x3B, (byte) 0x30, (byte) 0x19, (byte) 0xD4,
            (byte) 0xE7, (byte) 0x39, (byte) 0xDA, (byte) 0x73, (byte) 0x9C,
            (byte) 0xED, (byte) 0x39, (byte) 0xCE, (byte) 0x73, (byte) 0x9D,
            (byte) 0x83, (byte) 0x68, (byte) 0x58, (byte) 0x21, (byte) 0x08,
            (byte) 0x42, (byte) 0x10, (byte) 0x84, (byte) 0x21, (byte) 0x38,
            (byte) 0x42, (byte) 0x10, (byte) 0xC3, (byte) 0xF5, (byte) 0x34,
            (byte) 0x10, (byte) 0xFB, (byte) 0x0C, (byte) 0xB0, (byte) 0x46,
            (byte) 0x75, (byte) 0x85, (byte) 0xD3, (byte) 0x8D, (byte) 0xE2,
            (byte) 0xA4, (byte) 0x96, (byte) 0x83, (byte) 0x5E, (byte) 0x0D,
            (byte) 0xA7, (byte) 0x78, (byte) 0x35, (byte) 0x08, (byte) 0x32,
            (byte) 0x30, (byte) 0x33, (byte) 0x30, (byte) 0x30, (byte) 0x31,
            (byte) 0x30, (byte) 0x31, (byte) 0x3E, (byte) 0x00, (byte) 0xFE,
            (byte) 0x00
        }));                
    }
}
