package net.bither.bitherj.utils;

public class MinerFeeUtils {

    public static long getFinalMinerFee(long fee, boolean isNoPrivKey) {
        long finalMinerFee = Math.max(fee, 546);
        if (!isNoPrivKey) {
            return finalMinerFee;
        }
        String minerFeeHex = Long.toHexString(finalMinerFee);
        if (Utils.isEmpty(minerFeeHex)) {
            return finalMinerFee;
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
            return finalMinerFee;
        }
        try {
            byte[] bytes = Utils.hexStringToByteArray(minerFeeHex);
            int first = bytes[0] + 1;
            byte[] newBytes = new byte[bytes.length];
            newBytes[0] = (byte) first;
            return Long.parseLong(Utils.bytesToHexString(newBytes), 16);
        } catch (Exception ex) {
            ex.printStackTrace();
            return finalMinerFee;
        }
    }

}
