/*
 *
 *  * Copyright 2014 http://Bither.net
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *    http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package net.bither.bitherj.utils;

/**
 * Created by songchenwen on 14-11-12.
 */
public class UnitUtil {
    public static enum BitcoinUnit {
        BTC(100000000), bits(100);

        public long satoshis;

        BitcoinUnit(long satoshis) {
            this.satoshis = satoshis;
        }
    }

    public static String formatValue(final long value, BitcoinUnit unit) {
        String sign = value < 0 ? "-" : "";
        long absValue = Math.abs(value);
        long coins = absValue / unit.satoshis;
        long satoshis = absValue % unit.satoshis;
        String strCoins = Long.toString(coins);
        String strSatoshis = "";
        strSatoshis = Long.toString(satoshis + unit.satoshis);
        strSatoshis = strSatoshis.substring(1, strSatoshis.length());
        if (unit.satoshis > Math.pow(10, 2)) {
            strSatoshis = strSatoshis.replaceFirst("[0]{1," + Integer.toString((int) Math.floor
                    (Math.log10(unit.satoshis) - 2)) + "}$", "");
        }
        return sign + strCoins + (strSatoshis.length() > 0 ? "." : "") + strSatoshis;
    }
}
