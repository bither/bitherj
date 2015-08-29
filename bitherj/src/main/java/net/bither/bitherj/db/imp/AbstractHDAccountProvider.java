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

package net.bither.bitherj.db.imp;

import com.google.common.base.Function;

import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IHDAccountProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IDb;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.List;

import javax.annotation.Nullable;

public abstract class AbstractHDAccountProvider extends AbstractProvider implements IHDAccountProvider {

    @Override
    public String getHDFirstAddress(int hdSeedId) {
        String sql = "select hd_address from hd_account where hd_account_id=?";
        final String[] address = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.HD_ADDRESS);
                if (idColumn != -1) {
                    address[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return address[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor cursor = db.rawQuery("select hd_address from hd_account where hd_account_id=?"
//                , new String[]{Integer.toString(hdSeedId)});
//        String address = null;
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.HDAccountColumns.HD_ADDRESS);
//            if (idColumn != -1) {
//                address = cursor.getString(idColumn);
//            }
//        }
//        cursor.close();
//        return address;
    }

    @Override
    public int addHDAccount(String encryptedMnemonicSeed, String encryptSeed, String firstAddress
            , boolean isXrandom, String addressOfPS, byte[] externalPub
            , byte[] internalPub) {
        if (this.isPubExist(externalPub, internalPub)) {
            return -1;
        }
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        int hdAccountId = this.insertHDAccountToDb(writeDb, encryptedMnemonicSeed, encryptSeed
                , firstAddress, isXrandom, externalPub, internalPub);
        if (!this.hasPasswordSeed(writeDb) && !Utils.isEmpty(addressOfPS)) {
            this.addPasswordSeed(writeDb, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
        }
        writeDb.endTransaction();
        return hdAccountId;

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDAccountColumns.ENCRYPT_SEED, encryptSeed);
//        cv.put(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED, encryptedMnemonicSeed);
//        cv.put(AbstractDb.HDAccountColumns.IS_XRANDOM, isXrandom ? 1 : 0);
//        cv.put(AbstractDb.HDAccountColumns.HD_ADDRESS, firstAddress);
//        cv.put(AbstractDb.HDAccountColumns.EXTERNAL_PUB, Base58.encode(externalPub));
//        cv.put(AbstractDb.HDAccountColumns.INTERNAL_PUB, Base58.encode(internalPub));
//        int seedId = (int) db.insert(AbstractDb.Tables.HD_ACCOUNT, null, cv);
//        if (!AddressProvider.hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//            AddressProvider.addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
//        }
//        db.setTransactionSuccessful();
//        db.endTransaction();
//        return seedId;
    }

    protected abstract int insertHDAccountToDb(IDb db, String encryptedMnemonicSeed, String encryptSeed
            , String firstAddress, boolean isXrandom, byte[] externalPub, byte[] internalPub);

    protected abstract boolean hasPasswordSeed(IDb db);
//    protected boolean hasPasswordSeed(IDb db) {
//        String sql = "select count(0) cnt from password_seed where password_seed is not null";
//        final int[] count = {0};
//        this.execQueryOneRecord(db, sql, null, new Function<ICursor, Void>() {
//            @Nullable
//            @Override
//            public Void apply(@Nullable ICursor c) {
//                int idColumn = c.getColumnIndex("cnt");
//                if (idColumn != -1) {
//                    count[0] = c.getInt(idColumn);
//                }
//                return null;
//            }
//        });
//        return count[0] > 0;
//    }
    protected abstract void addPasswordSeed(IDb db, PasswordSeed passwordSeed);
//    protected void addPasswordSeed(IDb db, PasswordSeed passwordSeed) {
//        if (!Utils.isEmpty(passwordSeed.toPasswordSeedString())) {
//            String sql = "update password_seed set password_seed=?";
//            this.execUpdate(db, sql, new String[] {passwordSeed.toPasswordSeedString()});
//        }
//    }

    @Override
    public int addMonitoredHDAccount(String firstAddress, boolean isXrandom, byte[] externalPub, byte[] internalPub) {
        if (this.isPubExist(externalPub, internalPub)) {
            return -1;
        }
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        int hdAccountId = this.insertMonitorHDAccountToDb(writeDb, firstAddress, isXrandom, externalPub, internalPub);
        writeDb.endTransaction();
        return hdAccountId;

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDAccountColumns.HD_ADDRESS, firstAddress);
//        cv.put(AbstractDb.HDAccountColumns.IS_XRANDOM, isXrandom ? 1 : 0);
//        cv.put(AbstractDb.HDAccountColumns.EXTERNAL_PUB, Base58.encode(externalPub));
//        cv.put(AbstractDb.HDAccountColumns.INTERNAL_PUB, Base58.encode(internalPub));
//        int seedId = (int) db.insert(AbstractDb.Tables.HD_ACCOUNT, null, cv);
//        db.setTransactionSuccessful();
//        db.endTransaction();
//        return seedId;
    }

    protected abstract int insertMonitorHDAccountToDb(IDb db, String firstAddress, boolean isXrandom, byte[] externalPub, byte[] internalPub);

//    @Override
//    public boolean hasHDAccountCold() {
//        boolean result = false;
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        String sql = "select count(hd_address) cnt from hd_account where encrypt_seed is not " +
//                "null and encrypt_mnemonic_seed is not null";
//        Cursor cursor = db.rawQuery(sql, null);
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex("cnt");
//            if (idColumn != -1) {
//                result = cursor.getInt(idColumn) > 0;
//            }
//        }
//        cursor.close();
//        return result;
//    }

    @Override
    public boolean hasMnemonicSeed(int hdAccountId) {
        String sql = "select count(0) cnt from hd_account where encrypt_mnemonic_seed is not null and hd_account_id=?";
        final boolean[] result = {false};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdAccountId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    result[0] = c.getInt(idColumn) > 0;
                }
                return null;
            }
        });
        return result[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//
//        Cursor cursor = db.rawQuery(sql, new String[] {Integer.toString(hdAccountId)});
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex("cnt");
//            if (idColumn != -1) {
//                result = cursor.getInt(idColumn) > 0;
//            }
//        }
//        cursor.close();
//        return result;
    }

    @Override
    public byte[] getExternalPub(int hdSeedId) {
        final byte[][] pub = {null};
        String sql = "select external_pub from hd_account where hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.EXTERNAL_PUB);
                if (idColumn != -1) {
                    String pubStr = c.getString(idColumn);
                    try {
                        pub[0] = Base58.decode(pubStr);
                    } catch (AddressFormatException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        return pub[0];

//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            Cursor c = db.rawQuery("select external_pub from hd_account where hd_account_id=? "
//                    , new String[]{Integer.toString(hdSeedId)});
//            if (c.moveToNext()) {
//                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.EXTERNAL_PUB);
//                if (idColumn != -1) {
//                    String pubStr = c.getString(idColumn);
//                    pub = Base58.decode(pubStr);
//                }
//            }
//            c.close();
//        } catch (AddressFormatException e) {
//            e.printStackTrace();
//        }
//
//        return pub;
    }

    @Override
    public byte[] getInternalPub(int hdSeedId) {
        final byte[][] pub = {null};
        String sql = "select internal_pub from hd_account where hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.INTERNAL_PUB);
                if (idColumn != -1) {
                    String pubStr = c.getString(idColumn);
                    try {
                        pub[0] = Base58.decode(pubStr);
                    } catch (AddressFormatException e) {
                        e.printStackTrace();
                    }
                }
                return null;
            }
        });
        return pub[0];
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            Cursor c = db.rawQuery("select internal_pub from hd_account where hd_account_id=? "
//                    , new String[]{Integer.toString(hdSeedId)});
//            if (c.moveToNext()) {
//                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.INTERNAL_PUB);
//                if (idColumn != -1) {
//                    String pubStr = c.getString(idColumn);
//                    pub = Base58.decode(pubStr);
//                }
//            }
//            c.close();
//        } catch (AddressFormatException e) {
//            e.printStackTrace();
//        }
//
//
//        return pub;
    }


    @Override
    public String getHDAccountEncryptSeed(int hdSeedId) {
        final String[] hdAccountEncryptSeed = {null};
        String sql = "select encrypt_seed from hd_account where hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_SEED);
                if (idColumn != -1) {
                    hdAccountEncryptSeed[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return hdAccountEncryptSeed[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor c = db.rawQuery("select " + AbstractDb.HDAccountColumns.ENCRYPT_SEED + " from hd_account where hd_account_id=? "
//                , new String[]{Integer.toString(hdSeedId)});
//        if (c.moveToNext()) {
//            int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_SEED);
//            if (idColumn != -1) {
//                hdAccountEncryptSeed = c.getString(idColumn);
//            }
//        }
//        c.close();
//        return hdAccountEncryptSeed;
    }

    @Override
    public String getHDAccountEncryptMnemonicSeed(int hdSeedId) {
        final String[] hdAccountMnmonicEncryptSeed = {null};
        String sql = "select encrypt_mnemonic_seed from hd_account where hd_account_id=? ";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED);
                if (idColumn != -1) {
                    hdAccountMnmonicEncryptSeed[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return hdAccountMnmonicEncryptSeed[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor c = db.rawQuery("select " + AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED + " from hd_account where hd_account_id=? "
//                , new String[]{Integer.toString(hdSeedId)});
//        if (c.moveToNext()) {
//            int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED);
//            if (idColumn != -1) {
//                hdAccountMnmonicEncryptSeed = c.getString(idColumn);
//            }
//        }
//        c.close();
//        return hdAccountMnmonicEncryptSeed;
    }

    @Override
    public boolean hdAccountIsXRandom(int seedId) {
        final boolean[] result = {false};
        String sql = "select is_xrandom from hd_account where hd_account_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(seedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.IS_XRANDOM);
                if (idColumn != -1) {
                    result[0] = c.getInt(idColumn) == 1;
                }
                return null;
            }
        });
        return result[0];

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        String sql = "select is_xrandom from hd_account where hd_account_id=?";
//        Cursor cursor = db.rawQuery(sql, new String[]{Integer.toString(seedId)});
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.HDAccountColumns.IS_XRANDOM);
//            if (idColumn != -1) {
//                result[0] = cursor.getInt(idColumn) == 1;
//            }
//        }
//        cursor.close();
//        return result[0];
    }

    @Override
    public List<Integer> getHDAccountSeeds() {
        final List<Integer> hdSeedIds = new ArrayList<Integer>();
        String sql = "select hd_account_id from hd_account";
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                hdSeedIds.add(c.getInt(0));
                return null;
            }
        });
        return hdSeedIds;
//        Cursor c = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select " + AbstractDb.HDAccountColumns.HD_ACCOUNT_ID + " from " + AbstractDb.Tables.HD_ACCOUNT;
//            c = db.rawQuery(sql, null);
//            while (c.moveToNext()) {
//                hdSeedIds.add(c.getInt(0));
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//        return hdSeedIds;
    }

    @Override
    public boolean isPubExist(byte[] externalPub, byte[] internalPub) {
        String sql = "select count(0) cnt from hd_account where external_pub=? or internal_pub=?";
        final boolean[] isExist = {false};
        this.execQueryOneRecord(sql, new String[]{Base58.encode(externalPub), Base58.encode(internalPub)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                isExist[0] = c.getInt(0) > 0;
                return null;
            }
        });
        return isExist[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        String sql = "select count(0) cnt from hd_account where external_pub=? or internal_pub=?";
//        Cursor c = db.rawQuery(sql, new String[] {Base58.encode(externalPub), Base58.encode(internalPub)});
//        boolean isExist = false;
//        if (c.moveToNext()) {
//            isExist = c.getInt(0) > 0;
//        }
//        c.close();
//        return isExist;
    }
}
