package net.bither.bitherj.bech32;

import com.google.common.primitives.Bytes;

import net.bither.bitherj.exception.AddressFormatException;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class SegwitAddressUtil {

    private static SegwitAddressUtil instance = new SegwitAddressUtil();

    public static String SegwitAddressHrp = "bc";

    private SegwitAddressUtil() {}

    public static SegwitAddressUtil getInstance() {
        return instance;
    }

    public Pair<Byte, byte[]> decode(String hrp, String addr) throws Exception {
        Pair<byte[], byte[]> p = Bech32Util.getInstance().bech32Decode(addr);

        String hrpgot = new String(p.getLeft());
        if (!hrp.equalsIgnoreCase(hrpgot))    {
            throw new Exception("mismatching bech32 human readeable part");
        }
        if (!hrpgot.equalsIgnoreCase(SegwitAddressHrp) && !hrpgot.equalsIgnoreCase("tb"))    {
            throw new Exception("invalid segwit human readable part");
        }

        byte[] data = p.getRight();
        byte[] decoded = convertBits(Bytes.asList(Arrays.copyOfRange(data, 1, data.length)), 5, 8, false);
        if(decoded.length < 2 || decoded.length > 40)   {
            throw new Exception("invalid decoded data length");
        }

        byte witnessVersion = data[0];
        if (witnessVersion > 16)   {
            throw new Exception("invalid decoded witness version");
        }

        if (witnessVersion == 0 && decoded.length != 20 && decoded.length != 32)   {
            throw new Exception("decoded witness version 0 with unknown length");
        }

        return Pair.of(witnessVersion, decoded);
    }

    public String encode(byte[] hrp, byte witnessVersion, byte[] witnessProgram) throws Exception    {
        byte[] prog = convertBits(Bytes.asList(witnessProgram), 8, 5, true);
        byte[] data = new byte[1 + prog.length];

        System.arraycopy(new byte[] { witnessVersion }, 0, data, 0, 1);
        System.arraycopy(prog, 0, data, 1, prog.length);

        return Bech32Util.getInstance().bech32Encode(hrp, data);
    }

    public String encode(byte[] hrp, int witnessVersion, byte[] witnessProgram) throws Exception    {
        byte[] convertedProgram = convertBits(witnessProgram, 0, witnessProgram.length, 8, 5, true);
        byte[] bytes = new byte[1 + convertedProgram.length];
        bytes[0] = (byte) (witnessVersion & 0xff);
        System.arraycopy(convertedProgram, 0, bytes, 1, convertedProgram.length);

        return Bech32Util.getInstance().bech32Encode(hrp, bytes);
    }

    public byte[] getScriptPubkey(byte witver, byte[] witprog) {
        byte v = (witver > 0) ? (byte)(witver + 0x50) : (byte)0;
        byte[] ver = new byte[] { v, (byte)witprog.length };

        byte[] ret = new byte[witprog.length + ver.length];
        System.arraycopy(ver, 0, ret, 0, ver.length);
        System.arraycopy(witprog, 0, ret, ver.length, witprog.length);

        return ret;
    }

    public byte[] convertBits(List<Byte> data, int fromBits, int toBits, boolean pad) throws Exception    {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        List<Byte> ret = new ArrayList<Byte>();

        for(Byte value : data)  {
            short b = (short)(value & 0xff);

            if (b < 0) {
                throw new Exception();
            }
            else if ((b >> fromBits) > 0) {
                throw new Exception();
            }

            acc = (acc << fromBits) | b;
            bits += fromBits;
            while (bits >= toBits)  {
                bits -= toBits;
                ret.add((byte)((acc >> bits) & maxv));
            }
        }

        if(pad && (bits > 0))    {
            ret.add((byte)((acc << (toBits - bits)) & maxv));
        }
        else if (bits >= fromBits || (byte)(((acc << (toBits - bits)) & maxv)) != 0)    {
            throw new Exception("panic");
        }
        return Bytes.toArray(ret);
    }

    public static int getWitnessVersion(byte[] bytes) {
        return bytes[0] & 0xff;
    }

    public static byte[] getWitnessProgram(byte[] bytes) throws AddressFormatException {
        return convertBits(bytes, 1, bytes.length - 1, 5, 8, false);
    }

    /**
     * Helper for re-arranging bits into groups.
     */
    private static byte[] convertBits(final byte[] in, final int inStart, final int inLen, final int fromBits,
                                      final int toBits, final boolean pad) throws AddressFormatException {
        int acc = 0;
        int bits = 0;
        ByteArrayOutputStream out = new ByteArrayOutputStream(64);
        final int maxv = (1 << toBits) - 1;
        final int max_acc = (1 << (fromBits + toBits - 1)) - 1;
        for (int i = 0; i < inLen; i++) {
            int value = in[i + inStart] & 0xff;
            if ((value >>> fromBits) != 0) {
                throw new AddressFormatException(
                        String.format("Input value '%X' exceeds '%d' bit size", value, fromBits));
            }
            acc = ((acc << fromBits) | value) & max_acc;
            bits += fromBits;
            while (bits >= toBits) {
                bits -= toBits;
                out.write((acc >>> bits) & maxv);
            }
        }
        if (pad) {
            if (bits > 0)
                out.write((acc << (toBits - bits)) & maxv);
        } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) != 0) {
            throw new AddressFormatException("Could not convert bits, invalid padding");
        }
        return out.toByteArray();
    }

}
