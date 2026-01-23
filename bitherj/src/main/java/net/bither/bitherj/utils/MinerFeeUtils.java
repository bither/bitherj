package net.bither.bitherj.utils;

import static net.bither.bitherj.core.Tx.MIN_NONDUST_OUTPUT;

public class MinerFeeUtils {

    public static long getFinalMinerFee(long fee, boolean isNoPrivKey) {
        long finalMinerFee = Math.max(fee, MIN_NONDUST_OUTPUT);
        if (!isNoPrivKey) {
            return finalMinerFee;
        } else {
            return getNoPrivKeyMinerFee(finalMinerFee);
        }
    }

    private static long getNoPrivKeyMinerFee(long minerFee) {
        String minerFeeHex = Long.toHexString(minerFee);
        if (Utils.isEmpty(minerFeeHex)) {
            return minerFee;
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
            return minerFee;
        }
        return getNoPrivKeyMinerFee(minerFee + 10);
    }

}
