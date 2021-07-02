package net.bither.bitherj.utils;

public class MinerFeeUtils {

    public static long getFinalMinerFee(long fee) {
        if (fee <= 0) {
            return fee;
        }
        String minerFeeHex = Long.toHexString(fee);
        if (Utils.isEmpty(minerFeeHex)) {
            return fee;
        }
        boolean isAddress = false;
        if (minerFeeHex.length() % 2 == 0) {
            try {
                String address = Base58.hexToBase58WithAddress(minerFeeHex);
                isAddress = Utils.validBicoinAddress(address);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        if (!isAddress) {
            return fee;
        }
        try {
            byte[] bytes = Utils.hexStringToByteArray(minerFeeHex);
            int first = bytes[0] + 1;
            byte[] newBytes = new byte[bytes.length];
            newBytes[0] = (byte) first;
            Long dynamicFee = Long.parseLong(Utils.bytesToHexString(newBytes), 16);
            return dynamicFee;
        } catch (Exception ex) {
            ex.printStackTrace();
            return fee;
        }
    }

}
