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

public class CharSequenceUtil {

    public static int getRating(CharSequence password) {
        if (password == null || password.length() < 6) {
            return 0;
        }
        int strength = 0;
        if (password.length() > 9) {
            strength++;
        }
        int digitCount = getDigitCount(password);
        int symbolCount = getSymbolCount(password);
        boolean upperAndLower = bothUpperAndLower(password);
        if (digitCount > 0 && digitCount != password.length()) {
            strength++;
        }
        if (symbolCount > 0 && symbolCount != password.length()) {
            strength++;
        }
        if (upperAndLower) {
            strength++;
        }
        return strength;
    }

    private static boolean bothUpperAndLower(CharSequence password) {
        if (password == null || password.length() == 0) {
            return false;
        }
        boolean upper = false;
        boolean lower = false;
        int length = password.length();
        for (int i = 0;
             i < length;
             i++) {
            char c = password.charAt(i);
            if (!upper) {
                upper = Character.isUpperCase(c);
            }
            if (!lower) {
                lower = Character.isLowerCase(c);
            }
            if (upper && lower) {
                break;
            }
        }
        return upper && lower;
    }

    private static int getDigitCount(CharSequence password) {
        if (password == null || password.length() == 0) {
            return 0;
        }
        int numDigits = 0;
        int length = password.length();
        for (int i = 0;
             i < length;
             i++) {
            if (Character.isDigit(password.charAt(i))) {
                numDigits++;
            }
        }
        return numDigits;
    }

    private static int getSymbolCount(CharSequence password) {
        if (password == null || password.length() == 0) {
            return 0;
        }
        int numSymbol = 0;
        int length = password.length();
        for (int i = 0;
             i < length;
             i++) {
            char c = password.charAt(i);
            if (!Character.isLetter(c) && !Character.isDigit(c)) {
                numSymbol++;
            }
        }
        return numSymbol;
    }
}
