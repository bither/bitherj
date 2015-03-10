/*
 * Copyright 2014 http://Bither.net
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.bither.bitherj.utils;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Locale;

import javax.annotation.Nonnull;

public class GenericUtils {
    private GenericUtils() {

    }

    public static final BigInteger ONE_BTC = new BigInteger("100000000", 10);
    public static final BigInteger ONE_MBTC = new BigInteger("100000", 10);

    public static final int ONE_BTC_INT = ONE_BTC.intValue();
    public static final int ONE_MBTC_INT = ONE_MBTC.intValue();

    public static String formatValue(@Nonnull final long value, final int precision,
                                     final int shift) {
        return formatValue(value, "", "-", precision, shift);
    }

    public static String formatValue(@Nonnull long value, @Nonnull final String plusSign,
                                     @Nonnull final String minusSign, final int precision,
                                     final int shift) {

        final String sign = value < 0 ? minusSign : plusSign;

        if (shift == 0) {
            if (precision == 2) {
                value = value - value % 1000000 + value % 1000000 / 500000 * 1000000;
            } else if (precision == 4) {
                value = value - value % 10000 + value % 10000 / 5000 * 10000;
            } else if (precision == 6) {
                value = value - value % 100 + value % 100 / 50 * 100;
            } else if (precision == 8) {
                ;
            } else {
                throw new IllegalArgumentException("cannot handle precision/shift: " + precision
                        + "/" + shift);
            }

            final long absValue = Math.abs(value);
            final long coins = absValue / ONE_BTC_INT;
            final int satoshis = (int) (absValue % ONE_BTC_INT);

            if (satoshis % 1000000 == 0) {
                return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis / 1000000);
            } else if (satoshis % 10000 == 0) {
                return String.format(Locale.US, "%s%d.%04d", sign, coins, satoshis / 10000);
            } else if (satoshis % 100 == 0) {
                return String.format(Locale.US, "%s%d.%06d", sign, coins, satoshis / 100);
            } else {
                return String.format(Locale.US, "%s%d.%08d", sign, coins, satoshis);
            }
        } else if (shift == 3) {
            if (precision == 2) {
                value = value - value % 1000 + value % 1000 / 500 * 1000;
            } else if (precision == 4) {
                value = value - value % 10 + value % 10 / 5 * 10;
            } else if (precision == 5) {
                ;
            } else {
                throw new IllegalArgumentException("cannot handle precision/shift: " + precision
                        + "/" + shift);
            }

            final long absValue = Math.abs(value);
            final long coins = absValue / ONE_MBTC_INT;
            final int satoshis = (int) (absValue % ONE_MBTC_INT);

            if (satoshis % 1000 == 0) {
                return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis / 1000);
            } else if (satoshis % 10 == 0) {
                return String.format(Locale.US, "%s%d.%04d", sign, coins, satoshis / 10);
            } else {
                return String.format(Locale.US, "%s%d.%05d", sign, coins, satoshis);
            }
        } else if (shift == 6) {
            if (precision != 2) {
                throw new IllegalArgumentException("cannot handle precision/shift: " + precision
                        + "/" + shift);
            }
            int coin = (ONE_BTC_INT / (int) Math.floor(Math.pow(10, shift)));
            final long absValue = Math.abs(value);
            final long coins = absValue / coin;
            final int satoshis = (int) (absValue % coin);
            return String.format(Locale.US, "%s%d.%02d", sign, coins, satoshis);
        } else {
            throw new IllegalArgumentException("cannot handle shift: " + shift);
        }
    }

    public static BigInteger toNanoCoins(final String value, final int shift) {
        final BigInteger nanoCoins = new BigDecimal(value).movePointRight(8 - shift)
                .toBigIntegerExact();

        if (nanoCoins.signum() < 0) {
            throw new IllegalArgumentException("negative amount: " + value);
        }

        return nanoCoins;
    }


}
