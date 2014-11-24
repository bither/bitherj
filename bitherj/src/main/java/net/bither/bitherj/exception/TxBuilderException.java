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

package net.bither.bitherj.exception;

import net.bither.bitherj.utils.Utils;

public class TxBuilderException extends Exception {
    public static final int ERR_TX_DUST_OUT_CODE = 2001;
    public static final int ERR_TX_NOT_ENOUGH_MONEY_CODE = 2002;
    public static final int ERR_TX_WAIT_CONFIRM_CODE = 2003;
    public static final int ERR_TX_CAN_NOT_CALCULATE_CODE = 2004;
    public static final int ERR_REACH_MAX_TX_SIZE_LIMIT_CODE = 2005;

    public static enum TxBuilderErrorType {
        TxCannotCalculate, TxDustOut, TxNotEnoughMoney, TxWaitConfirm, TxMaxSize;

        private String format;

        public static TxBuilderErrorType fromErrorCode(int code) {
            switch (code) {
                case ERR_TX_DUST_OUT_CODE:
                    return TxDustOut;
                case ERR_TX_NOT_ENOUGH_MONEY_CODE:
                    return TxNotEnoughMoney;
                case ERR_TX_WAIT_CONFIRM_CODE:
                    return TxWaitConfirm;
                case ERR_REACH_MAX_TX_SIZE_LIMIT_CODE:
                    return TxMaxSize;
                default:
                    return TxCannotCalculate;
            }
        }

        public void registerFormatString(String format) {
            this.format = format;
        }

        public String getFormatString() {
            return format;
        }
    }

    public TxBuilderErrorType type;

    public TxBuilderException() {
        this(TxBuilderErrorType.TxCannotCalculate);
    }

    public TxBuilderException(int errorCode) {
        this(TxBuilderErrorType.fromErrorCode(errorCode));
    }

    public TxBuilderException(TxBuilderErrorType type) {
        super();
        this.type = type;
    }

    @Override
    public String getMessage() {
        String format = getFormatString();
        if (Utils.isEmpty(format)) {
            return type.name();
        } else {
            return formatMessage(format);
        }
    }

    protected String formatMessage(String format) {
        return format;
    }

    private String getFormatString() {
        return type.getFormatString();
    }

    public static final void registerFormatString(TxBuilderErrorType type, String format) {
        type.registerFormatString(format);
    }

    public static class TxBuilderNotEnoughMoneyException extends TxBuilderException {
        public long lackOf;

        public TxBuilderNotEnoughMoneyException(long lackOfMoney) {
            super(TxBuilderErrorType.TxNotEnoughMoney);
            this.lackOf = lackOfMoney;
        }

        @Override
        protected String formatMessage(String format) {
            return String.format(format, Utils.bitcoinValueToPlainString(lackOf));
        }
    }

    public static class TxBuilderWaitConfirmException extends TxBuilderException {
        public long toWait;

        public TxBuilderWaitConfirmException(long amountToWait) {
            super(TxBuilderErrorType.TxWaitConfirm);
            this.toWait = amountToWait;
        }

        @Override
        protected String formatMessage(String format) {
            return String.format(format, Utils.bitcoinValueToPlainString(toWait));
        }
    }
}
