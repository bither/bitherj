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

import net.bither.bitherj.core.Address;
import net.bither.bitherj.core.HDMAddress;
import net.bither.bitherj.core.HDMBId;
import net.bither.bitherj.core.HDMKeychain;
import net.bither.bitherj.crypto.EncryptedData;
import net.bither.bitherj.crypto.PasswordSeed;
import net.bither.bitherj.db.AbstractDb;
import net.bither.bitherj.db.IAddressProvider;
import net.bither.bitherj.db.imp.base.ICursor;
import net.bither.bitherj.db.imp.base.IDb;
import net.bither.bitherj.db.imp.base.IProvider;
import net.bither.bitherj.exception.AddressFormatException;
import net.bither.bitherj.utils.Base58;
import net.bither.bitherj.utils.Utils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

public abstract class AbstractAddressProvider implements IProvider, IAddressProvider {

    @Override
    public boolean changePassword(CharSequence oldPassword, CharSequence newPassword) {
        IDb readDb = this.getReadDb();
        final HashMap<String, String> addressesPrivKeyHashMap = new HashMap<String, String>();
        String sql = "select address,encrypt_private_key,pub_key,is_xrandom from addresses where encrypt_private_key is not null";
        this.execQueryLoop(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(ICursor c) {
                String address = c.getString(0);
                String encryptPrivateKey = c.getString(1);
                boolean isCompress = true;
                try {
                    byte[] pubKey = Base58.decode(c.getString(2));
                    isCompress = pubKey.length == 33;
                } catch (AddressFormatException e) {
                    e.printStackTrace();
                }
                int isXRandom = c.getInt(3);
                addressesPrivKeyHashMap.put(address, new EncryptedData(encryptPrivateKey).toEncryptedStringForQRCode(isCompress, isXRandom == 1));
                return null;
            }
        });
//        Cursor c = readDb.rawQuery(sql, null);
//        while (c.moveToNext()) {
//            String address = c.getString(0);
//            String encryptPrivateKey = c.getString(1);
//            boolean isCompress = true;
//            try {
//                byte[] pubKey = Base58.decode(c.getString(2));
//                isCompress = pubKey.length == 33;
//            } catch (AddressFormatException e) {
//                e.printStackTrace();
//            }
//            int isXRandom = c.getInt(3);
//            addressesPrivKeyHashMap.put(address, new EncryptedData(encryptPrivateKey).toEncryptedStringForQRCode(isCompress, isXRandom == 1));
//        }
//        c.close();

        final String[] hdmEncryptPassword = {null};
        sql = "select encrypt_bither_password from hdm_bid limit 1";
        this.execQueryOneRecord(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                hdmEncryptPassword[0] = c.getString(0);
                return null;
            }
        });
//        c = readDb.rawQuery(sql, null);
//        if (c.moveToNext()) {
//            hdmEncryptPassword[0] = c.getString(0);
//        }
//        c.close();

        final HashMap<Integer, String> encryptMenmonicSeedHashMap = new HashMap<Integer, String>();
        final HashMap<Integer, String> encryptHDSeedHashMap = new HashMap<Integer, String>();
        final HashMap<Integer, String> singularModeBackupHashMap = new HashMap<Integer, String>();
        sql = "select hd_seed_id,encrypt_seed,encrypt_hd_seed,singular_mode_backup from hd_seeds where encrypt_seed!='RECOVER'";
        this.execQueryLoop(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Integer hdSeedId = c.getInt(0);
                String encryptSeed = c.getString(1);
                if (!c.isNull(2)) {
                    String encryptHDSeed = c.getString(2);
                    encryptHDSeedHashMap.put(hdSeedId, encryptHDSeed);
                }
                if (!c.isNull(3)) {
                    String singularModeBackup = c.getString(3);
                    singularModeBackupHashMap.put(hdSeedId, singularModeBackup);
                }
                encryptMenmonicSeedHashMap.put(hdSeedId, encryptSeed);
                return null;
            }
        });
//        c = readDb.rawQuery(sql, null);
//        while (c.moveToNext()) {
//            Integer hdSeedId = c.getInt(0);
//            String encryptSeed = c.getString(1);
//            if (!c.isNull(2)) {
//                String encryptHDSeed = c.getString(2);
//                encryptHDSeedHashMap.put(hdSeedId, encryptHDSeed);
//            }
//            if (!c.isNull(3)) {
//                String singularModeBackup = c.getString(3);
//                singularModeBackupHashMap.put(hdSeedId, singularModeBackup);
//            }
//            encryptMenmonicSeedHashMap.put(hdSeedId, encryptSeed);
//        }
//        c.close();

        final HashMap<Integer, String> hdEncryptSeedHashMap = new HashMap<Integer, String>();
        final HashMap<Integer, String> hdEncryptMnemonicSeedHashMap = new HashMap<Integer, String>();
        sql = "select hd_account_id,encrypt_seed,encrypt_mnemonic_seed from hd_account where encrypt_mnemonic_seed is not null";
        this.execQueryLoop(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.HD_ACCOUNT_ID);
                Integer hdAccountId = 0;
                if (idColumn != -1) {
                    hdAccountId = c.getInt(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_SEED);
                if (idColumn != -1) {
                    String encryptSeed = c.getString(idColumn);
                    hdEncryptSeedHashMap.put(hdAccountId, encryptSeed);
                }
                idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED);
                if (idColumn != -1) {
                    String encryptHDSeed = c.getString(idColumn);
                    hdEncryptMnemonicSeedHashMap.put(hdAccountId, encryptHDSeed);
                }
                return null;
            }
        });
//        c = readDb.rawQuery("select hd_account_id,encrypt_seed,encrypt_mnemonic_seed from hd_account where encrypt_mnemonic_seed is not null", null);
//        while (c.moveToNext()) {
//            int idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.HD_ACCOUNT_ID);
//            Integer hdAccountId = 0;
//            if (idColumn != -1) {
//                hdAccountId = c.getInt(idColumn);
//            }
//            idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_SEED);
//            if (idColumn != -1) {
//                String encryptSeed = c.getString(idColumn);
//                hdEncryptSeedHashMap.put(hdAccountId, encryptSeed);
//            }
//            idColumn = c.getColumnIndex(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED);
//            if (idColumn != -1) {
//                String encryptHDSeed = c.getString(idColumn);
//                hdEncryptMnemonicSeedHashMap.put(hdAccountId, encryptHDSeed);
//            }
//
//        }
//        c.close();

        final HashMap<Integer, String> enterpriseHDEncryptSeedHashMap = new HashMap<Integer, String>();
        final HashMap<Integer, String> enterpriseHDEncryptMnemonicSeedHashMap = new HashMap<Integer, String>();
        sql = "select hd_account_id,encrypt_seed,encrypt_mnemonic_seed from enterprise_hd_account";
        this.execQueryLoop(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.HD_ACCOUNT_ID);
                Integer hdAccountId = 0;
                if (idColumn != -1) {
                    hdAccountId = c.getInt(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_SEED);
                if (idColumn != -1) {
                    String encryptSeed = c.getString(idColumn);
                    if (!Utils.isEmpty(encryptSeed)) {
                        enterpriseHDEncryptSeedHashMap.put(hdAccountId, encryptSeed);
                    }
                }
                idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_MNEMONIC_SEED);
                if (idColumn != -1) {
                    String encryptHDMnemonicSeed = c.getString(idColumn);
                    if (Utils.isEmpty(encryptHDMnemonicSeed)) {
                        enterpriseHDEncryptMnemonicSeedHashMap.put(hdAccountId, encryptHDMnemonicSeed);
                    }
                }
                return null;
            }
        });
//        c = readDb.rawQuery("select hd_account_id,encrypt_seed,encrypt_mnemonic_seed from enterprise_hd_account  ", null);
//        while (c.moveToNext()) {
//            int idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.HD_ACCOUNT_ID);
//            Integer hdAccountId = 0;
//            if (idColumn != -1) {
//                hdAccountId = c.getInt(idColumn);
//            }
//            idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_SEED);
//            if (idColumn != -1) {
//                String encryptSeed = c.getString(idColumn);
//                if (!Utils.isEmpty(encryptSeed)) {
//                    enterpriseHDEncryptSeedHashMap.put(hdAccountId, encryptSeed);
//                }
//            }
//            idColumn = c.getColumnIndex(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_MNEMONIC_SEED);
//            if (idColumn != -1) {
//                String encryptHDMnemonicSeed = c.getString(idColumn);
//                if (Utils.isEmpty(encryptHDMnemonicSeed)) {
//                    enterpriseHDEncryptMnemonicSeedHashMap.put(hdAccountId, encryptHDMnemonicSeed);
//                }
//            }
//
//        }
//        c.close();

        final PasswordSeed[] passwordSeed = {null};
        sql = "select password_seed from password_seed limit 1";
        this.execQueryLoop(readDb, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                passwordSeed[0] = new PasswordSeed(c.getString(0));
                return null;
            }
        });
//        c = readDb.rawQuery(sql, null);
//        if (c.moveToNext()) {
//            passwordSeed[0] = new PasswordSeed(c.getString(0));
//        }
//        c.close();

        for (Map.Entry<String, String> kv : addressesPrivKeyHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwdKeepFlag(kv.getValue(), oldPassword, newPassword));
        }
        if (hdmEncryptPassword[0] != null) {
            hdmEncryptPassword[0] = EncryptedData.changePwd(hdmEncryptPassword[0], oldPassword, newPassword);
        }
        for (Map.Entry<Integer, String> kv : encryptMenmonicSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }
        for (Map.Entry<Integer, String> kv : encryptHDSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }
        for (Map.Entry<Integer, String> kv : hdEncryptSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }
        for (Map.Entry<Integer, String> kv : hdEncryptMnemonicSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }

        for (Map.Entry<Integer, String> kv : enterpriseHDEncryptSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }
        for (Map.Entry<Integer, String> kv : enterpriseHDEncryptMnemonicSeedHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }


        for (Map.Entry<Integer, String> kv : singularModeBackupHashMap.entrySet()) {
            kv.setValue(EncryptedData.changePwd(kv.getValue(), oldPassword, newPassword));
        }
        if (passwordSeed[0] != null) {
            boolean result = passwordSeed[0].changePassword(oldPassword, newPassword);
            if (!result) {
                return false;
            }
        }

        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        sql = "update addresses set encrypt_private_key=? where address=?";
        for (Map.Entry<String, String> kv : addressesPrivKeyHashMap.entrySet()) {
            this.execUpdate(writeDb, sql, new String[] {kv.getValue(), kv.getKey()});
//            cv = new ContentValues();
//            cv.put(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY, kv.getValue());
//            writeDb.update(AbstractDb.Tables.Addresses, cv, "address=?", new String[]{kv.getKey()});
        }
        sql = "update hdm_bid set encrypt_bither_password=?";
        if (hdmEncryptPassword[0] != null) {
            this.execUpdate(writeDb, sql, new String[]{hdmEncryptPassword[0]});
//            cv = new ContentValues();
//            cv.put(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD, hdmEncryptPassword[0]);
//            writeDb.update(AbstractDb.Tables.HDM_BID, cv, null, null);
        }
        String sqlPart1 = "update hd_seeds set encrypt_seed=? ";
        String sqlPart2 = " where hd_seed_id=?";
        for (Map.Entry<Integer, String> kv : encryptMenmonicSeedHashMap.entrySet()) {
            ArrayList<String> params = new ArrayList<String>();
            params.add(kv.getValue());
            sql = sqlPart1;
            if (encryptHDSeedHashMap.containsKey(kv.getKey())) {
                sql += ",encrypt_hd_seed=?";
                params.add(encryptHDSeedHashMap.get(kv.getKey()));
            }
            if (singularModeBackupHashMap.containsKey(kv.getKey())) {
                sql += ",singular_mode_backup=?";
                params.add(singularModeBackupHashMap.get(kv.getKey()));
            }
            sql += sqlPart2;
            params.add(Integer.toString(kv.getKey()));
            this.execUpdate(writeDb, sql, params.toArray(new String[params.size()]));
//            cv = new ContentValues();
//            cv.put(AbstractDb.HDSeedsColumns.ENCRYPT_MNEMONIC_SEED, kv.getValue());
//            if (encryptHDSeedHashMap.containsKey(kv.getKey())) {
//                cv.put(AbstractDb.HDSeedsColumns.ENCRYPT_HD_SEED, encryptHDSeedHashMap.get(kv.getKey()));
//            }
//            if (singularModeBackupHashMap.containsKey(kv.getKey())) {
//                cv.put(AbstractDb.HDSeedsColumns.SINGULAR_MODE_BACKUP, singularModeBackupHashMap.get(kv.getKey()));
//            }
//            writeDb.update(AbstractDb.Tables.HDSEEDS, cv, "hd_seed_id=?", new String[]{kv.getKey().toString()});
        }

        sqlPart1 = "update hd_account set encrypt_seed=? ";
        sqlPart2 = " where hd_account_id=?";
        for (Map.Entry<Integer, String> kv : hdEncryptSeedHashMap.entrySet()) {
            ArrayList<String> params = new ArrayList<String>();
            sql = sqlPart1;
            params.add(kv.getValue());
            if (hdEncryptMnemonicSeedHashMap.containsKey(kv.getKey())) {
                sql += ",encrypt_mnemonic_seed=?";
                params.add(hdEncryptMnemonicSeedHashMap.get(kv.getKey()));
            }
            sql += sqlPart2;
            params.add(Integer.toString(kv.getKey()));
            this.execUpdate(writeDb, sql, params.toArray(new String[params.size()]));
//            cv = new ContentValues();
//            cv.put(AbstractDb.HDAccountColumns.ENCRYPT_SEED, kv.getValue());
//            if (hdEncryptMnemonicSeedHashMap.containsKey(kv.getKey())) {
//                cv.put(AbstractDb.HDAccountColumns.ENCRYPT_MNMONIC_SEED
//                        , hdEncryptMnemonicSeedHashMap.get(kv.getKey()));
//            }
//            writeDb.update(AbstractDb.Tables.HD_ACCOUNT,
//                    cv, "hd_account_id=?", new String[]{kv.getKey().toString()});
        }

        sqlPart1 = "update enterprise_hd_account set encrypt_seed=? ";
        sqlPart2 = " where hd_account_id=?";
        for (Map.Entry<Integer, String> kv : enterpriseHDEncryptSeedHashMap.entrySet()) {
            ArrayList<String> params = new ArrayList<String>();
            sql = sqlPart1;
            params.add(kv.getValue());
            if (enterpriseHDEncryptMnemonicSeedHashMap.containsKey(kv.getKey())) {
                sql += ",encrypt_mnemonic_seed=?";
                params.add(enterpriseHDEncryptMnemonicSeedHashMap.get(kv.getKey()));
            }
            sql += sqlPart2;
            params.add(Integer.toString(kv.getKey()));
            this.execUpdate(writeDb, sql, params.toArray(new String[params.size()]));
//            cv = new ContentValues();
//            cv.put(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_SEED, kv.getValue());
//            if (hdEncryptMnemonicSeedHashMap.containsKey(kv.getKey())) {
//                cv.put(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_MNEMONIC_SEED
//                        , hdEncryptMnemonicSeedHashMap.get(kv.getKey()));
//            }
//            writeDb.update(AbstractDb.Tables.ENTERPRISE_HD_ACCOUNT,
//                    cv, "hd_account_id=?", new String[]{kv.getKey().toString()});
        }

        sql = "update password_seed set password_seed=?";
        if (passwordSeed[0] != null) {
            this.execUpdate(writeDb, sql, new String[]{passwordSeed[0].toPasswordSeedString()});
//            cv = new ContentValues();
//            cv.put(AbstractDb.PasswordSeedColumns.PASSWORD_SEED, passwordSeed[0].toPasswordSeedString());
//            writeDb.update(AbstractDb.Tables.PASSWORD_SEED, cv, null, null);
        }

//        writeDb.setTransactionSuccessful();
        writeDb.endTransaction();
        return true;
    }

    @Override
    public PasswordSeed getPasswordSeed() {
        final PasswordSeed[] passwordSeed = {null};
        String sql = "select password_seed from password_seed limit 1";
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                passwordSeed[0] = applyPasswordSeed(c);
                return null;
            }
        });
        return passwordSeed[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor c = db.rawQuery("select password_seed from password_seed limit 1", null);
//        PasswordSeed passwordSeed = null;
//        if (c.moveToNext()) {
//            passwordSeed = applyPasswordSeed(c);
//        }
//        c.close();
//        return passwordSeed;
    }

    public boolean hasPasswordSeed(IDb db) {
        String sql = "select count(0) cnt from password_seed where password_seed is not null";
        final int[] count = {0};
        this.execQueryOneRecord(db, sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    count[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return count[0] > 0;
//        Cursor c = db.rawQuery("select  count(0) cnt from password_seed  where " +
//                "password_seed is not null ", null);
//        int count = 0;
//        if (c.moveToNext()) {
//            int idColumn = c.getColumnIndex("cnt");
//            if (idColumn != -1) {
//                count = c.getInt(idColumn);
//            }
//        }
//        c.close();
//        return count > 0;
    }

    public boolean hasPasswordSeed() {
        return this.hasPasswordSeed(this.getReadDb());
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        return AddressProvider.hasPasswordSeed(db);
    }

    public void addPasswordSeed(IDb db, PasswordSeed passwordSeed) {
        if (!Utils.isEmpty(passwordSeed.toPasswordSeedString())) {
            String sql = "update password_seed set password_seed=?";
            this.execUpdate(db, sql, new String[] {passwordSeed.toPasswordSeedString()});
        }
//
//        ContentValues cv = applyPasswordSeedCV(passwordSeed);
//        db.insert(AbstractDb.Tables.PASSWORD_SEED, null, cv);
    }

    @Override
    public List<Integer> getHDSeeds() {
        final List<Integer> hdSeedIds = new ArrayList<Integer>();
        String sql = "select hd_seed_id from hd_seeds";
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDSeedsColumns.HD_SEED_ID);
                if (idColumn != -1) {
                    hdSeedIds.add(c.getInt(idColumn));
                }
                return null;
            }
        });
        return hdSeedIds;
//        Cursor c = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select " + AbstractDb.HDSeedsColumns.HD_SEED_ID + " from " + AbstractDb.Tables.HDSEEDS;
//            c = db.rawQuery(sql, null);
//            while (c.moveToNext()) {
//                int idColumn = c.getColumnIndex(AbstractDb.HDSeedsColumns.HD_SEED_ID);
//                if (idColumn != -1) {
//                    hdSeedIds.add(c.getInt(idColumn));
//                }
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
    public String getEncryptMnemonicSeed(int hdSeedId) {
        final String[] encryptSeed = {null};
        String sql = "select encrypt_seed from hd_seeds where hd_seed_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                encryptSeed[0] = c.getString(0);
                return null;
            }
        });
        return encryptSeed[0];
//        String encryptSeed = null;
//        Cursor c = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select encrypt_seed from hd_seeds where hd_seed_id=?";
//            c = db.rawQuery(sql, new String[]{Integer.toString(hdSeedId)});
//            if (c.moveToNext()) {
//                encryptSeed = c.getString(0);
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//        return encryptSeed;
    }

    @Override
    public String getEncryptHDSeed(int hdSeedId) {
        final String[] encryptHDSeed = {null};
        String sql = "select encrypt_hd_seed from hd_seeds where hd_seed_id=?";
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                encryptHDSeed[0] = c.getString(0);
                return null;
            }
        });
        return encryptHDSeed[0];
//        Cursor c = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select encrypt_hd_seed from hd_seeds where hd_seed_id=?";
//            c = db.rawQuery(sql, new String[]{Integer.toString(hdSeedId)});
//            if (c.moveToNext()) {
//                encryptHDSeed[0] = c.getString(0);
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//        return encryptHDSeed[0];
    }


    @Override
    public void updateEncrypttMnmonicSeed(int hdSeedId, String encryptMnmonicSeed) {
        String sql = "update hd_seeds set encrypt_hd_seed=? where hd_seed_id=?";
        this.execUpdate(sql, new String[] {encryptMnmonicSeed, Integer.toString(hdSeedId)});
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDSeedsColumns.ENCRYPT_HD_SEED, encryptMnmonicSeed);
//        db.update(AbstractDb.Tables.HDSEEDS, cv, "hd_seed_id=?"
//                , new String[]{Integer.toString(hdSeedId)});
    }


    @Override
    public boolean isHDSeedFromXRandom(int hdSeedId) {
        String sql = "select is_xrandom from hd_seeds where hd_seed_id=?";
        final boolean[] isXRandom = {false};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("is_xrandom");
                if (idColumn != -1) {
                    isXRandom[0] = c.getInt(idColumn) == 1;
                }
                return null;
            }
        });
        return isXRandom[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor cursor = db.rawQuery("select is_xrandom from hd_seeds where hd_seed_id=?"
//                , new String[]{Integer.toString(hdSeedId)});
//        boolean isXRandom = false;
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex("is_xrandom");
//            if (idColumn != -1) {
//                isXRandom = cursor.getInt(idColumn) == 1;
//            }
//        }
//        return isXRandom;
    }


    @Override
    public String getHDMFristAddress(int hdSeedId) {
        String sql = "select hdm_address from hd_seeds where hd_seed_id=?";
        final String[] address = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDSeedsColumns.HDM_ADDRESS);
                if (idColumn != -1) {
                    address[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return address[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor cursor = db.rawQuery("select hdm_address from hd_seeds where hd_seed_id=?"
//                , new String[]{Integer.toString(hdSeedId)});
//        String address = null;
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.HDSeedsColumns.HDM_ADDRESS);
//            if (idColumn != -1) {
//                address = cursor.getString(idColumn);
//            }
//        }
//        cursor.close();
//        return address;
    }

    @Override
    public String getSingularModeBackup(int hdSeedId) {
        String sql = "select singular_mode_backup from hd_seeds where hd_seed_id=?";
        final String[] singularModeBackup = {null};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                singularModeBackup[0] = c.getString(0);
                return null;
            }
        });
        return singularModeBackup[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor cursor = db.rawQuery("select singular_mode_backup from hd_seeds where hd_seed_id=?"
//                , new String[]{Integer.toString(hdSeedId)});
//        String singularModeBackup = null;
//        if (cursor.moveToNext()) {
//            singularModeBackup = cursor.getString(0);
//        }
//        cursor.close();
//        return singularModeBackup;
    }

    @Override
    public void setSingularModeBackup(int hdSeedId, String singularModeBackup) {
        String sql = "update hd_seeds set singular_mode_backup=? where hd_seed_id=?";
        this.execUpdate(sql, new String[]{singularModeBackup, Integer.toString(hdSeedId)});

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDSeedsColumns.SINGULAR_MODE_BACKUP, singularModeBackup);
//        db.update(AbstractDb.Tables.HDSEEDS, cv, "hd_seed_id=?", new String[]{Integer.toString(hdSeedId)});
    }

    @Override
    public int addHDKey(String encryptedMnemonicSeed, String encryptHdSeed, String firstAddress, boolean isXrandom, String addressOfPS) {
        IDb db = this.getWriteDb();
        db.beginTransaction();
        int seedId = this.insertHDKeyToDb(db, encryptedMnemonicSeed, encryptHdSeed, firstAddress, isXrandom);
        if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
            this.addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
        }
        db.endTransaction();
        return seedId;


//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDSeedsColumns.ENCRYPT_MNEMONIC_SEED, encryptedMnemonicSeed);
//        cv.put(AbstractDb.HDSeedsColumns.ENCRYPT_HD_SEED, encryptHdSeed);
//        cv.put(AbstractDb.HDSeedsColumns.IS_XRANDOM, isXrandom ? 1 : 0);
//        cv.put(AbstractDb.HDSeedsColumns.HDM_ADDRESS, firstAddress);
//        int seedId = (int) db.insert(AbstractDb.Tables.HDSEEDS, null, cv);
//        if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//            AddressProvider.addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
//        }
//        db.setTransactionSuccessful();
//        db.endTransaction();
//        return seedId;
    }

    protected abstract int insertHDKeyToDb(IDb db, String encryptedMnemonicSeed, String encryptHdSeed, String firstAddress, boolean isXrandom);

    @Override
    public int addEnterpriseHDKey(String encryptedMnemonicSeed, String encryptHdSeed, String firstAddress, boolean isXrandom, String addressOfPS) {
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        int seedId = this.insertEnterpriseHDKeyToDb(writeDb, encryptedMnemonicSeed, encryptHdSeed, firstAddress, isXrandom);
        if (!hasPasswordSeed(writeDb) && !Utils.isEmpty(addressOfPS)) {
            addPasswordSeed(writeDb, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
        }
        writeDb.endTransaction();
        return seedId;
//
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_MNEMONIC_SEED, encryptedMnemonicSeed);
//        cv.put(AbstractDb.EnterpriseHDAccountColumns.ENCRYPT_SEED, encryptHdSeed);
//        cv.put(AbstractDb.EnterpriseHDAccountColumns.IS_XRANDOM, isXrandom ? 1 : 0);
//        cv.put(AbstractDb.EnterpriseHDAccountColumns.HD_ADDRESS, firstAddress);
//        int seedId = (int) db.insert(AbstractDb.Tables.ENTERPRISE_HD_ACCOUNT, null, cv);
//        if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//            addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedMnemonicSeed));
//        }
//        db.setTransactionSuccessful();
//        db.endTransaction();
//        return seedId;
    }

    protected abstract int insertEnterpriseHDKeyToDb(IDb db, String encryptedMnemonicSeed, String encryptHdSeed, String firstAddress, boolean isXrandom);

    @Override
    public HDMBId getHDMBId() {
        String sql = "select hdm_bid,encrypt_bither_password from hdm_bid";
        HDMBId hdmbId = null;
        final String[] address = {null};
        final String[] encryptBitherPassword = {null};
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDMBIdColumns.HDM_BID);
                if (idColumn != -1) {
                    address[0] = c.getString(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD);
                if (idColumn != -1) {
                    encryptBitherPassword[0] = c.getString(idColumn);
                }
                return null;
            }
        });

        if (!Utils.isEmpty(address[0]) && !Utils.isEmpty(encryptBitherPassword[0])) {
            hdmbId = new HDMBId(address[0], encryptBitherPassword[0]);
        }
        return hdmbId;
//
//        HDMBId hdmbId = null;
//        Cursor c = null;
//        String address = null;
//        String encryptBitherPassword = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select " + AbstractDb.HDMBIdColumns.HDM_BID + "," + AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD + " from " +
//                    AbstractDb.Tables.HDM_BID;
//            c = db.rawQuery(sql, null);
//            if (c.moveToNext()) {
//                int idColumn = c.getColumnIndex(AbstractDb.HDMBIdColumns.HDM_BID);
//                if (idColumn != -1) {
//                    address = c.getString(idColumn);
//                }
//                idColumn = c.getColumnIndex(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD);
//                if (idColumn != -1) {
//                    encryptBitherPassword = c.getString(idColumn);
//                }
//
//            }
//            if (!Utils.isEmpty(address) && !Utils.isEmpty(encryptBitherPassword)) {
//                hdmbId = new HDMBId(address, encryptBitherPassword);
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//
//        return hdmbId;
    }


    @Override
    public void addAndUpdateHDMBId(HDMBId hdmBid, String addressOfPS) {
        String sql = "select count(0) from hdm_bid";
        final boolean[] isExist = {true};
        this.execQueryOneRecord(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                isExist[0] = c.getInt(0) > 0;
                return null;
            }
        });
        if (!isExist[0]) {
            String encryptedBitherPasswordString = hdmBid.getEncryptedBitherPasswordString();
            IDb writeDb = this.getWriteDb();
            sql = "insert into hdm_bid(hdm_bid,encrypt_bither_password) values(?,?)";
            writeDb.beginTransaction();
            this.execUpdate(writeDb, sql, new String[]{hdmBid.getAddress(), encryptedBitherPasswordString});
            if (!hasPasswordSeed(writeDb) && !Utils.isEmpty(addressOfPS)) {
                addPasswordSeed(writeDb, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
            }
            writeDb.endTransaction();
//            db.beginTransaction();
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMBIdColumns.HDM_BID, hdmBid.getAddress());
//            cv.put(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD, encryptedBitherPasswordString);
//            db.insert(AbstractDb.Tables.HDM_BID, null, cv);
//            if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//                addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
        } else {
            String encryptedBitherPasswordString = hdmBid.getEncryptedBitherPasswordString();
            IDb writeDb = this.getWriteDb();
            sql = "update hdm_bid set encrypt_bither_password=? where hdm_bid=?";
            writeDb.beginTransaction();;
            this.execUpdate(writeDb, sql, new String[]{encryptedBitherPasswordString, hdmBid.getAddress()});
            if (!hasPasswordSeed(writeDb) && !Utils.isEmpty(addressOfPS)) {
                addPasswordSeed(writeDb, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
            }
            writeDb.endTransaction();
//
//            db.beginTransaction();
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD, encryptedBitherPasswordString);
//            db.update(AbstractDb.Tables.HDM_BID, cv, AbstractDb.HDMBIdColumns.HDM_BID + "=?", new String[]{
//                    hdmBid.getAddress()
//            });
//            if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//                addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
        }

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        boolean isExist = true;
//        Cursor c = null;
//        try {
//            String sql = "select count(0) from " + AbstractDb.Tables.HDM_BID;
//            c = db.rawQuery(sql, null);
//            if (c.moveToNext()) {
//                isExist = c.getInt(0) > 0;
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//        if (!isExist) {
//            String encryptedBitherPasswordString = hdmBid.getEncryptedBitherPasswordString();
//            db.beginTransaction();
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMBIdColumns.HDM_BID, hdmBid.getAddress());
//            cv.put(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD, encryptedBitherPasswordString);
//            db.insert(AbstractDb.Tables.HDM_BID, null, cv);
//            if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//                addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
//        } else {
//            String encryptedBitherPasswordString = hdmBid.getEncryptedBitherPasswordString();
//            db.beginTransaction();
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMBIdColumns.ENCRYPT_BITHER_PASSWORD, encryptedBitherPasswordString);
//            db.update(AbstractDb.Tables.HDM_BID, cv, AbstractDb.HDMBIdColumns.HDM_BID + "=?", new String[]{
//                    hdmBid.getAddress()
//            });
//            if (!hasPasswordSeed(db) && !Utils.isEmpty(addressOfPS)) {
//                addPasswordSeed(db, new PasswordSeed(addressOfPS, encryptedBitherPasswordString));
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
//        }
    }

    @Override
    public List<HDMAddress> getHDMAddressInUse(HDMKeychain keychain) {
        String sql = "select hd_seed_index,pub_key_hot,pub_key_cold,pub_key_remote,address,is_synced " +
                " from hdm_addresses " +
                " where hd_seed_id=? and address is not null order by hd_seed_index";
        final List<HDMAddress> addresses = new ArrayList<HDMAddress>();
        final HDMKeychain hdmKeychain = keychain;
        this.execQueryLoop(sql, new String[]{Integer.toString(keychain.getHdSeedId())}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                HDMAddress hdmAddress = applyHDMAddress(c, hdmKeychain);
                if (hdmAddress != null) {
                    addresses.add(hdmAddress);
                }
                return null;
            }
        });
        return addresses;

//        List<HDMAddress> addresses = new ArrayList<HDMAddress>();
//        Cursor c = null;
//        try {
//            SQLiteDatabase db = this.mDb.getReadableDatabase();
//            String sql = "select hd_seed_index,pub_key_hot,pub_key_cold,pub_key_remote,address,is_synced " +
//                    "from hdm_addresses " +
//                    "where hd_seed_id=? and address is not null order by hd_seed_index";
//            c = db.rawQuery(sql, new String[]{Integer.toString(keychain.getHdSeedId())});
//            while (c.moveToNext()) {
//                HDMAddress hdmAddress = applyHDMAddress(c, keychain);
//                if (hdmAddress != null) {
//                    addresses.add(hdmAddress);
//                }
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//        } finally {
//            if (c != null)
//                c.close();
//        }
//        return addresses;
    }


    @Override
    public void prepareHDMAddresses(int hdSeedId, List<HDMAddress.Pubs> pubsList) {
        String sql = "select count(0) from hdm_addresses where hd_seed_id=? and hd_seed_index=?";
        final boolean[] isExist = {false};
        for (HDMAddress.Pubs pubs : pubsList) {
            this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(pubs.index)}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    isExist[0] |= c.getInt(0) > 0;
                    return null;
                }
            });
            if (!isExist[0]) {
                break;
            }
        }
        if (!isExist[0]) {
            IDb writeDb = this.getWriteDb();
            writeDb.beginTransaction();
            for (int i = 0; i < pubsList.size(); i++) {
                HDMAddress.Pubs pubs = pubsList.get(i);
                this.insertHDMAddressToDb(writeDb, null, hdSeedId, pubs.index, pubs.hot, pubs.cold, null, false);
            }
            writeDb.endTransaction();
        }

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        boolean isExist = false;
//        Cursor c = null;
//        try {
//            for (HDMAddress.Pubs pubs : pubsList) {
//                String sql = "select count(0) from hdm_addresses where hd_seed_id=? and hd_seed_index=?";
//                c = db.rawQuery(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(pubs.index)});
//                if (c.moveToNext()) {
//                    isExist |= c.getInt(0) > 0;
//                }
//                c.close();
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            isExist = true;
//        } finally {
//            if (c != null && !c.isClosed())
//                c.close();
//        }
//        if (!isExist) {
//            db.beginTransaction();
//            for (int i = 0; i < pubsList.size(); i++) {
//                HDMAddress.Pubs pubs = pubsList.get(i);
//                ContentValues cv = applyHDMAddressContentValues(null, hdSeedId, pubs.index, pubs.hot, pubs.cold, null, false);
//                db.insert(AbstractDb.Tables.HDMADDRESSES, null, cv);
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
//        }

    }

    protected abstract void insertHDMAddressToDb(IDb db, String address, int hdSeedId, int index, byte[] pubKeysHot,
                                 byte[] pubKeysCold, byte[] pubKeysRemote, boolean isSynced);

    @Override
    public List<HDMAddress.Pubs> getUncompletedHDMAddressPubs(int hdSeedId, int count) {
        String sql = "select * from hdm_addresses where hd_seed_id=? and pub_key_remote is null limit ? ";
        final List<HDMAddress.Pubs> pubsList = new ArrayList<HDMAddress.Pubs>();

        this.execQueryLoop(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(count)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                HDMAddress.Pubs pubs = applyPubs(c);
                if (pubs != null) {
                    pubsList.add(pubs);
                }
                return null;
            }
        });
        return pubsList;

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        List<HDMAddress.Pubs> pubsList = new ArrayList<HDMAddress.Pubs>();
//        Cursor cursor = db.rawQuery("select * from hdm_addresses where hd_seed_id=? and pub_key_remote is null limit ? ", new String[]{
//                Integer.toString(hdSeedId), Integer.toString(count)
//        });
//        try {
//            while (cursor.moveToNext()) {
//                HDMAddress.Pubs pubs = applyPubs(cursor);
//                if (pubs != null) {
//                    pubsList.add(pubs);
//                }
//            }
//        } catch (AddressFormatException e) {
//            e.printStackTrace();
//        }
//
//        cursor.close();
//        return pubsList;
    }

    @Override
    public int maxHDMAddressPubIndex(int hdSeedId) {
        String sql = "select ifnull(max(hd_seed_index),-1)  hd_seed_index from hdm_addresses where hd_seed_id=?  ";
        final int[] maxIndex = {-1};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.HD_SEED_INDEX);
                if (idColumn != -1) {
                    maxIndex[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return maxIndex[0];
//
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//
//        Cursor cursor = db.rawQuery("select ifnull(max(hd_seed_index),-1)  hd_seed_index from hdm_addresses where hd_seed_id=?  ", new String[]{
//                Integer.toString(hdSeedId)
//        });
//        int maxIndex = -1;
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.HDMAddressesColumns.HD_SEED_INDEX);
//            if (idColumn != -1) {
//                maxIndex = cursor.getInt(idColumn);
//            }
//        }
//        cursor.close();
//        return maxIndex;
    }

    @Override
    public int uncompletedHDMAddressCount(int hdSeedId) {
        String sql = "select count(0) cnt from hdm_addresses where hd_seed_id=?  and pub_key_remote is null ";
        final int[] count = {0};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex("cnt");
                if (idColumn != -1) {
                    count[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return count[0];
//
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor cursor = db.rawQuery("select count(0) cnt from hdm_addresses where hd_seed_id=?  and pub_key_remote is null "
//                , new String[]{
//                Integer.toString(hdSeedId)
//        });
//        int count = 0;
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex("cnt");
//            if (idColumn != -1) {
//                count = cursor.getInt(idColumn);
//            }
//        }
//        cursor.close();
//        return count;
    }

    public void setHDMPubsRemote(int hdSeedId, int index, byte[] remote) {
        String sql = "select count(0) from hdm_addresses " +
                "where hd_seed_id=? and hd_seed_index=? and pub_key_remote is null";
        final boolean[] isExist = {true};
        this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(index)}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                isExist[0] = c.getInt(0) > 0;
                return null;
            }
        });
        if (isExist[0]) {
            sql = "update hdm_addresses set pub_key_remote=? where hd_seed_id=? and hd_seed_index=?";
            this.execUpdate(sql, new String[]{Base58.encode(remote), Integer.toString(hdSeedId), Integer.toString(index)});
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE, Base58.encode(remote));
//            db.update(AbstractDb.Tables.HDMADDRESSES, cv, " hd_seed_id=? and hd_seed_index=? "
//                    , new String[]{Integer.toString(hdSeedId), Integer.toString(index)});
        }
//
//
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        boolean isExist = true;
//        Cursor c = null;
//        try {
//            String sql = "select count(0) from hdm_addresses " +
//                    "where hd_seed_id=? and hd_seed_index=? and pub_key_remote is null";
//            c = db.rawQuery(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(index)});
//            if (c.moveToNext()) {
//                isExist = c.getInt(0) > 0;
//            }
//            c.close();
//
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            isExist = false;
//        } finally {
//            if (c != null && !c.isClosed())
//                c.close();
//        }
//        if (isExist[0]) {
//            ContentValues cv = new ContentValues();
//            cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE, Base58.encode(remote));
//            db.update(AbstractDb.Tables.HDMADDRESSES, cv, " hd_seed_id=? and hd_seed_index=? "
//                    , new String[]{Integer.toString(hdSeedId), Integer.toString(index)});
//
//        }
    }

    @Override
    public void completeHDMAddresses(int hdSeedId, List<HDMAddress> addresses) {
        String sql = "select count(0) from hdm_addresses " +
                "where hd_seed_id=? and hd_seed_index=? and pub_key_remote is null";
        final boolean[] isExist = {true};
        for (HDMAddress address : addresses) {
            this.execQueryOneRecord(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(address.getIndex())}, new Function<ICursor, Void>() {
                @Nullable
                @Override
                public Void apply(@Nullable ICursor c) {
                    isExist[0] &= c.getInt(0) > 0;
                    return null;
                }
            });
            if (!isExist[0]) {
                break;
            }
        }
        if (isExist[0]) {
            IDb writeDb = this.getWriteDb();
            writeDb.beginTransaction();
            sql = "update hdm_addresses set pub_key_remote=?,address where hd_seed_id=? and hd_seed_index=?";
            for (int i = 0; i < addresses.size(); i++) {
                HDMAddress address = addresses.get(i);
                this.execUpdate(writeDb, sql, new String[]{Base58.encode(address.getPubRemote())
                        , address.getAddress(), Integer.toString(hdSeedId), Integer.toString(address.getIndex())});
            }
            writeDb.endTransaction();
        }

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        boolean isExist = true;
//        Cursor c = null;
//        try {
//            for (HDMAddress address : addresses) {
//
//                String sql = "select count(0) from hdm_addresses " +
//                        "where hd_seed_id=? and hd_seed_index=? and pub_key_remote is null";
//                c = db.rawQuery(sql, new String[]{Integer.toString(hdSeedId), Integer.toString(address.getIndex())});
//                if (c.moveToNext()) {
//                    isExist &= c.getInt(0) > 0;
//                }
//                c.close();
//            }
//        } catch (Exception ex) {
//            ex.printStackTrace();
//            isExist = false;
//        } finally {
//            if (c != null && !c.isClosed())
//                c.close();
//        }
//        if (isExist) {
//            db.beginTransaction();
//            for (int i = 0; i < addresses.size(); i++) {
//                HDMAddress address = addresses.get(i);
//                ContentValues cv = new ContentValues();
//                cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE, Base58.encode(address.getPubRemote()));
//                cv.put(AbstractDb.HDMAddressesColumns.ADDRESS, address.getAddress());
//                db.update(AbstractDb.Tables.HDMADDRESSES, cv, " hd_seed_id=? and hd_seed_index=? "
//                        , new String[]{Integer.toString(hdSeedId), Integer.toString(address.getIndex())});
//            }
//            db.setTransactionSuccessful();
//            db.endTransaction();
//        }
    }

    @Override
    public void recoverHDMAddresses(int hdSeedId, List<HDMAddress> addresses) {
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        for (int i = 0; i < addresses.size(); i++) {
            HDMAddress address = addresses.get(i);
            this.insertHDMAddressToDb(writeDb, address.getAddress(), hdSeedId, address.getIndex()
                    , address.getPubHot(), address.getPubCold(), address.getPubRemote(), false);
        }
        writeDb.endTransaction();

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        for (int i = 0; i < addresses.size(); i++) {
//            HDMAddress address = addresses.get(i);
//            ContentValues cv = applyHDMAddressContentValues(address.getAddress(), hdSeedId,
//                    address.getIndex(), address.getPubHot(), address.getPubCold(), address.getPubRemote(), false);
//            db.insert(AbstractDb.Tables.HDMADDRESSES, null, cv);
//
//        }
//        db.setTransactionSuccessful();
//        db.endTransaction();
    }

//    private ContentValues applyHDMAddressContentValues(String address, int hdSeedId, int index, byte[] pubKeysHot,
//                                                       byte[] pubKeysCold, byte[] pubKeysRemote, boolean isSynced) {
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDMAddressesColumns.HD_SEED_ID, hdSeedId);
//        cv.put(AbstractDb.HDMAddressesColumns.HD_SEED_INDEX, index);
//        cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_HOT, Base58.encode(pubKeysHot));
//        cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_COLD, Base58.encode(pubKeysCold));
//        if (Utils.isEmpty(address)) {
//            cv.putNull(AbstractDb.HDMAddressesColumns.ADDRESS);
//        } else {
//            cv.put(AbstractDb.HDMAddressesColumns.ADDRESS, address);
//        }
//        if (pubKeysRemote == null) {
//            cv.putNull(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE);
//        } else {
//            cv.put(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE, Base58.encode(pubKeysRemote));
//        }
//        cv.put(AbstractDb.HDMAddressesColumns.IS_SYNCED, isSynced ? 1 : 0);
//        return cv;
//    }


    @Override
    public void syncComplete(int hdSeedId, int hdSeedIndex) {
        String sql = "update hdm_addresses set is_synced=? where hd_seed_id=? and hd_seed_index=?";
        this.execUpdate(sql, new String[]{"1", Integer.toString(hdSeedId), Integer.toString(hdSeedIndex)});
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.HDMAddressesColumns.IS_SYNCED, 1);
//        db.update(AbstractDb.Tables.HDMADDRESSES, cv, " hd_seed_id=? and hd_seed_index=? "
//                , new String[]{Integer.toString(hdSeedId), Integer.toString(hdSeedIndex)});
    }

    //normal
    @Override
    public List<Address> getAddresses() {
        String sql = "select address,encrypt_private_key,pub_key,is_xrandom,is_trash,is_synced,sort_time " +
                "from addresses  order by sort_time desc";
        final List<Address> addressList = new ArrayList<Address>();
        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                Address address = null;
                try {
                    address = applyAddressCursor(c);
                } catch (AddressFormatException e) {
                    e.printStackTrace();
                }
                if (address != null) {
                    addressList.add(address);
                }
                return null;
            }
        });
        return addressList;

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor c = db.rawQuery("select address,encrypt_private_key,pub_key,is_xrandom,is_trash,is_synced,sort_time " +
//                "from addresses  order by sort_time desc", null);
//        List<Address> addressList = new ArrayList<Address>();
//        while (c.moveToNext()) {
//            Address address = null;
//            try {
//                address = applyAddressCursor(c);
//            } catch (AddressFormatException e) {
//                e.printStackTrace();
//            }
//            if (address != null) {
//                addressList.add(address);
//            }
//        }
//        c.close();
//        return addressList;
    }

    public String getEncryptPrivateKey(String address) {
        String sql = "select encrypt_private_key from addresses where address=?";
        final String[] encryptPrivateKey = {null};
        this.execQueryOneRecord(sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY);
                if (idColumn != -1) {
                    encryptPrivateKey[0] = c.getString(idColumn);
                }
                return null;
            }
        });
        return encryptPrivateKey[0];
//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Cursor c = db.rawQuery("select encrypt_private_key from addresses  where address=?", new String[]{address});
//        String encryptPrivateKey = null;
//        if (c.moveToNext()) {
//            int idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY);
//            if (idColumn != -1) {
//                encryptPrivateKey = c.getString(idColumn);
//            }
//        }
//        return encryptPrivateKey;
    }

    @Override
    public void addAddress(Address address) {
        IDb writeDb = this.getWriteDb();
        writeDb.beginTransaction();
        this.insertAddressToDb(writeDb, address);
        if (address.hasPrivKey()) {
            if (!hasPasswordSeed(writeDb)) {
                PasswordSeed passwordSeed = new PasswordSeed(address.getAddress(), address.getFullEncryptPrivKeyOfDb());
                addPasswordSeed(writeDb, passwordSeed);
            }
        }
        writeDb.endTransaction();
//
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.beginTransaction();
//        ContentValues cv = applyContentValues(address);
//        db.insert(AbstractDb.Tables.Addresses, null, cv);
//        if (address.hasPrivKey()) {
//            if (!hasPasswordSeed(db)) {
//                PasswordSeed passwordSeed = new PasswordSeed(address.getAddress(), address.getFullEncryptPrivKeyOfDb());
//                addPasswordSeed(db, passwordSeed);
//            }
//        }
//        db.setTransactionSuccessful();
//        db.endTransaction();
    }

    protected abstract void insertAddressToDb(IDb db, Address address);

    @Override
    public void removeWatchOnlyAddress(Address address) {
        String sql = "delete from addresses where address=? and encrypt_private_key is null";
        this.execUpdate(sql, new String[]{address.getAddress()});

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        db.delete(AbstractDb.Tables.Addresses, AbstractDb.AddressesColumns.ADDRESS + "=? and "
//                + AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY + " is null", new String[]{
//                address.getAddress()
//        });
    }


    @Override
    public void trashPrivKeyAddress(Address address) {
        String sql = "update addresses set is_trash=? where address=?";
        this.execUpdate(sql, new String[]{"1", address.getAddress()});

//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.AddressesColumns.IS_TRASH, 1);
//        db.update(AbstractDb.Tables.Addresses, cv, AbstractDb.AddressesColumns.ADDRESS + "=?"
//                , new String[]{address.getAddress()});
    }

    @Override
    public void restorePrivKeyAddress(Address address) {
        String sql = "update addresses set is_trash=?,sort_time=?,is_synced=? where address=?";
        this.execUpdate(sql, new String[]{"0", Long.toString(address.getSortTime()), "0", address.getAddress()});
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.AddressesColumns.IS_TRASH, 0);
//        cv.put(AbstractDb.AddressesColumns.SORT_TIME, address.getSortTime());
//        cv.put(AbstractDb.AddressesColumns.IS_SYNCED, 0);
//        db.update(AbstractDb.Tables.Addresses, cv, AbstractDb.AddressesColumns.ADDRESS + "=?"
//                , new String[]{address.getAddress()});
    }

    @Override
    public void updateSyncComplete(Address address) {
        String sql = "update addresses set is_synced=? where address=?";
        this.execUpdate(sql, new String[]{address.isSyncComplete() ? "1" : "0", address.getAddress()});
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.AddressesColumns.IS_SYNCED, address.isSyncComplete() ? 1 : 0);
//        db.update(AbstractDb.Tables.Addresses, cv, AbstractDb.AddressesColumns.ADDRESS + "=?"
//                , new String[]{address.getAddress()});
    }

    @Override
    public void updatePrivateKey(String address, String encryptPriv) {
        String sql = "update addresses set encrypt_private_key=? where address=?";
        this.execUpdate(sql, new String[]{encryptPriv, address});
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY, encryptPriv);
//        db.update(AbstractDb.Tables.Addresses, cv, AbstractDb.AddressesColumns.ADDRESS + "=?"
//                , new String[]{address});
    }

    @Override
    public String getAlias(String address) {
        String sql = "select alias from aliases where address=?";
        final String[] alias = {null};
        this.execQueryOneRecord(sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                alias[0] = c.getString(0);
                return null;
            }
        });
        return alias[0];

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        String alias = null;
//        Cursor cursor = db.rawQuery("select alias from aliases where address=?", new String[]{address});
//
//        if (cursor.moveToNext()) {
//            alias = cursor.getString(0);
//        }
//        cursor.close();
//        return alias;
    }

    @Override
    public Map<String, String> getAliases() {
        String sql = "select * from aliases";
        final Map<String, String> aliasList = new HashMap<String, String>();

        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.AliasColumns.ADDRESS);
                String address = null;
                String alias = null;
                if (idColumn > -1) {
                    address = c.getString(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.AliasColumns.ALIAS);
                if (idColumn > -1) {
                    alias = c.getString(idColumn);
                }
                aliasList.put(address, alias);
                return null;
            }
        });
        return aliasList;

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Map<String, String> aliasList = new HashMap<String, String>();
//        Cursor cursor = db.rawQuery("select * from aliases", null);
//
//        while (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.AliasColumns.ADDRESS);
//            String address = null;
//            String alias = null;
//            if (idColumn > -1) {
//                address = cursor.getString(idColumn);
//            }
//            idColumn = cursor.getColumnIndex(AbstractDb.AliasColumns.ALIAS);
//            if (idColumn > -1) {
//                alias = cursor.getString(idColumn);
//            }
//            aliasList.put(address, alias);
//
//        }
//        cursor.close();
//        return aliasList;
    }

    @Override
    public void updateAlias(String address, @Nullable String alias) {
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
        if (alias == null) {
            String sql = "delete from aliases where address=?";
            this.execUpdate(sql, new String[]{address});
//            db.delete(AbstractDb.Tables.ALIASES, AbstractDb.AliasColumns.ADDRESS + "=? ", new String[]{address});
        } else {
            String sql = "insert or replace into aliases(address,alias) values(?,?)";
            this.execUpdate(sql, new String[]{address, alias});
//            db.execSQL("insert or replace into aliases(address,alias) values(?,?)", new String[]{address, alias});
        }
    }

    @Override
    public int getVanityLen(String address) {
        String sql = "select vanity_len from vanity_address where address=?";
        final int[] len = {Address.VANITY_LEN_NO_EXSITS};
        this.execQueryOneRecord(sql, new String[]{address}, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.VanityAddressColumns.VANITY_LEN);
                if (idColumn != -1) {
                    len[0] = c.getInt(idColumn);
                }
                return null;
            }
        });
        return len[0];

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        int len = Address.VANITY_LEN_NO_EXSITS;
//        Cursor cursor = db.rawQuery("select vanity_len from vanity_address where address=?", new String[]{address});
//        if (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.VanityAddressColumns.VANITY_LEN);
//            if (idColumn != -1) {
//                len = cursor.getInt(idColumn);
//            }
//        }
//        cursor.close();
//        return len;
    }

    @Override
    public Map<String, Integer> getVanitylens() {
        String sql = "select * from vanity_address";
        final Map<String, Integer> vanityLenMap = new HashMap<String, Integer>();

        this.execQueryLoop(sql, null, new Function<ICursor, Void>() {
            @Nullable
            @Override
            public Void apply(@Nullable ICursor c) {
                int idColumn = c.getColumnIndex(AbstractDb.VanityAddressColumns.ADDRESS);
                String address = null;
                int alias = Address.VANITY_LEN_NO_EXSITS;
                if (idColumn > -1) {
                    address = c.getString(idColumn);
                }
                idColumn = c.getColumnIndex(AbstractDb.VanityAddressColumns.VANITY_LEN);
                if (idColumn > -1) {
                    alias = c.getInt(idColumn);
                }
                vanityLenMap.put(address, alias);
                return null;
            }
        });
        return vanityLenMap;

//        SQLiteDatabase db = this.mDb.getReadableDatabase();
//        Map<String, Integer> vanityLenMap = new HashMap<String, Integer>();
//        Cursor cursor = db.rawQuery("select * from vanity_address", null);
//
//        while (cursor.moveToNext()) {
//            int idColumn = cursor.getColumnIndex(AbstractDb.VanityAddressColumns.ADDRESS);
//            String address = null;
//            int alias = Address.VANITY_LEN_NO_EXSITS;
//            if (idColumn > -1) {
//                address = cursor.getString(idColumn);
//            }
//            idColumn = cursor.getColumnIndex(AbstractDb.VanityAddressColumns.VANITY_LEN);
//            if (idColumn > -1) {
//                alias = cursor.getInt(idColumn);
//            }
//            vanityLenMap.put(address, alias);
//
//        }
//        cursor.close();
//        return vanityLenMap;
    }

    @Override
    public void updateVaitylen(String address, int vanitylen) {
//        SQLiteDatabase db = this.mDb.getWritableDatabase();
        if (vanitylen == Address.VANITY_LEN_NO_EXSITS) {
            String sql = "delete from vanity_address where address=?";
            this.execUpdate(sql, new String[]{address});
//            db.delete(AbstractDb.Tables.VANITY_ADDRESS, AbstractDb.AliasColumns.ADDRESS + "=? ", new String[]{address});
        } else {
            String sql = "insert or replace into vanity_address(address,vanity_len) values(?,?)";
            this.execUpdate(sql, new String[]{address, Integer.toString(vanitylen)});
//            db.execSQL("insert or replace into vanity_address(address,vanity_len) values(?,?)", new String[]{address
//                    , Integer.toString(vanitylen)});
        }

    }



//    private static ContentValues applyPasswordSeedCV(PasswordSeed passwordSeed) {
//        ContentValues cv = new ContentValues();
//        if (!Utils.isEmpty(passwordSeed.toPasswordSeedString())) {
//            cv.put(AbstractDb.PasswordSeedColumns.PASSWORD_SEED, passwordSeed.toPasswordSeedString());
//        }
//        return cv;
//    }

//    private ContentValues applyContentValues(Address address) {
//        ContentValues cv = new ContentValues();
//        cv.put(AbstractDb.AddressesColumns.ADDRESS, address.getAddress());
//        if (address.hasPrivKey()) {
//            cv.put(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY, address.getEncryptPrivKeyOfDb());
//        }
//        cv.put(AbstractDb.AddressesColumns.PUB_KEY, Base58.encode(address.getPubKey()));
//        cv.put(AbstractDb.AddressesColumns.IS_XRANDOM, address.isFromXRandom() ? 1 : 0);
//        cv.put(AbstractDb.AddressesColumns.IS_SYNCED, address.isSyncComplete() ? 1 : 0);
//        cv.put(AbstractDb.AddressesColumns.IS_TRASH, address.isTrashed() ? 1 : 0);
//        cv.put(AbstractDb.AddressesColumns.SORT_TIME, address.getSortTime());
//        return cv;
//
//    }

    private HDMAddress applyHDMAddress(ICursor c, HDMKeychain keychain) {
        HDMAddress hdmAddress;

        String address = null;
        boolean isSynced = false;

        int idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.ADDRESS);
        if (idColumn != -1) {
            address = c.getString(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.IS_SYNCED);
        if (idColumn != -1) {
            isSynced = c.getInt(idColumn) == 1;
        }
        HDMAddress.Pubs pubs = applyPubs(c);
        hdmAddress = new HDMAddress(pubs, address, isSynced, keychain);
        return hdmAddress;

    }

    public PasswordSeed applyPasswordSeed(ICursor c) {
        int idColumn = c.getColumnIndex(AbstractDb.PasswordSeedColumns.PASSWORD_SEED);
        String passwordSeed = null;
        if (idColumn != -1) {
            passwordSeed = c.getString(idColumn);
        }
        if (Utils.isEmpty(passwordSeed)) {
            return null;
        }
        return new PasswordSeed(passwordSeed);
    }

    private HDMAddress.Pubs applyPubs(ICursor c) {
        int hdSeedIndex = 0;
        byte[] hot = null;
        byte[] cold = null;
        byte[] remote = null;
        int idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.HD_SEED_INDEX);
        if (idColumn != -1) {
            hdSeedIndex = c.getInt(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.PUB_KEY_HOT);
        if (idColumn != -1 && !c.isNull(idColumn)) {
            try {
                hot = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.PUB_KEY_COLD);
        if (idColumn != -1 && !c.isNull(idColumn)) {
            try {
                cold = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.HDMAddressesColumns.PUB_KEY_REMOTE);
        if (idColumn != -1 && !c.isNull(idColumn)) {
            try {
                remote = Base58.decode(c.getString(idColumn));
            } catch (AddressFormatException e) {
                e.printStackTrace();
            }
        }
        return new HDMAddress.Pubs(hot, cold, remote, hdSeedIndex);

    }

    private Address applyAddressCursor(ICursor c) throws AddressFormatException {
        Address address;
        int idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.ADDRESS);
        String addressStr = null;
        String encryptPrivateKey = null;
        byte[] pubKey = null;
        boolean isXRandom = false;
        boolean isSynced = false;
        boolean isTrash = false;
        long sortTime = 0;

        if (idColumn != -1) {
            addressStr = c.getString(idColumn);
            if (!Utils.validBicoinAddress(addressStr)) {
                return null;
            }
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.ENCRYPT_PRIVATE_KEY);
        if (idColumn != -1) {
            encryptPrivateKey = c.getString(idColumn);
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.PUB_KEY);
        if (idColumn != -1) {
            pubKey = Base58.decode(c.getString(idColumn));
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.IS_XRANDOM);
        if (idColumn != -1) {
            isXRandom = c.getInt(idColumn) == 1;
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.IS_SYNCED);
        if (idColumn != -1) {
            isSynced = c.getInt(idColumn) == 1;
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.IS_TRASH);
        if (idColumn != -1) {
            isTrash = c.getInt(idColumn) == 1;
        }
        idColumn = c.getColumnIndex(AbstractDb.AddressesColumns.SORT_TIME);
        if (idColumn != -1) {
            sortTime = c.getLong(idColumn);
        }
        address = new Address(addressStr, pubKey, sortTime, isSynced, isXRandom, isTrash, encryptPrivateKey);

        return address;
    }
}
