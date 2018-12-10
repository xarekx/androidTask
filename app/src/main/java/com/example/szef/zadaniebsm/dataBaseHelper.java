package com.example.szef.zadaniebsm;

import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;

import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;

public class dataBaseHelper extends SQLiteOpenHelper {

    public String hash1;
    private static final String DATABASE_NAME = "bsm.sqlite";
    private static final String TABLE_NAME = "bsm_table";
    private static final int SALT_SIZE = 16;
    private static final int IV_SIZE = 16;


    public byte[] createSalt(int SaltSize) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[SaltSize];
        random.nextBytes(salt);
        return salt;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public void createKeyStore() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        final KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder("MyKeyAlias1",
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(128)
                //.setUserAuthenticationRequired(true) //requires lock screen, invalidated if lock screen is disabled
                //.setUserAuthenticationValidityDurationSeconds(120) //only available x seconds from password authentication. -1 requires finger print - every time
//                .setRandomizedEncryptionRequired(true) //different ciphertext for same plaintext on each call
                .build();
        keyGenerator.init(keyGenParameterSpec);
        keyGenerator.generateKey();
    }

    public static SecretKey getTheKey()
            throws KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, UnrecoverableEntryException {
        final KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        final KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry("MyKeyAlias1", null);
        final SecretKey secretKey = secretKeyEntry.getSecretKey();

        return secretKey;
    }
    public dataBaseHelper(Context context) throws CertificateException, UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException, IOException {
        super(context,DATABASE_NAME,null,1);
    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("create table " + TABLE_NAME + "(ID INTEGER PRIMARY KEY AUTOINCREMENT,PASSWORD TEXT,HASH TEXT,CONTENT TEXT,IV BLOB)");
    }
    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        db.execSQL("DROP TABLE IF EXISTS " + TABLE_NAME);
        onCreate(db);
    }
    // inserting password
    public boolean insertBsm (String password) throws NoSuchAlgorithmException {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put("PASSWORD",MainActivity.md5(hash1,password));
        contentValues.put("HASH",hash1);
        long result = db.insert(TABLE_NAME,null,contentValues);
        if(result == -1 ) {
            return false;
        } else {
            return true;
        }
    }
    // checking password
    public boolean checkPassword(String password) throws NoSuchAlgorithmException {
        password = MainActivity.md5(hash1,password);
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery("Select * From " +TABLE_NAME+ " where PASSWORD "+ " = ?" ,new String[]{password});
        if (cursor.getCount()>0) {
            return false;
        } else {
            return true;
        }
    }
    // Changing password
    public boolean change(String password,String newPassword) throws NoSuchAlgorithmException {
        password = MainActivity.md5(hash1,password);
        String newPass = MainActivity.md5(hash1, newPassword);
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery("Select * From " +TABLE_NAME+ " where PASSWORD "+ " = ?" ,new String[]{password});
        if(cursor.getCount()>0) {
            ContentValues values = new ContentValues();
            values.put("PASSWORD",newPass);
            values.put("HASH",hash1);
            db.update(TABLE_NAME,values,"PASSWORD=?",new String[]{password});
            return false;
        } else {
            System.out.println("Haslo nie wystąpiło");
            return true;
        }
    }

    public String createHash(String Password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        char[] bytePass = Password.toCharArray();

        byte[] hash = pbkdf2(bytePass,createSalt(SALT_SIZE),1500,16);

        String pass = hash.toString();
        return pass;
    }
    private static byte[] pbkdf2(char[] password, byte[] salt, int iterations, int bytes)
            throws InvalidKeySpecException, NoSuchAlgorithmException {

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password, salt, iterations, bytes * 8);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        return secretKeyFactory.generateSecret(pbeKeySpec).getEncoded();
    }
    // inserting Note
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public boolean insertContent (String content) throws Exception {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put("CONTENT", toBase64(encrypt(content.getBytes("UTF-8"))));
        long result = db.update(TABLE_NAME,contentValues,"ID=1",null);
        if(result == -1) {
            return false;
        } else {
            return true;
        }
    }
    public boolean insertIV(byte [] IVf) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues contentValues = new ContentValues();
        contentValues.put("IV",IVf);
        long result = db.update(TABLE_NAME,contentValues,"ID=1",null);
        if(result == -1) {
            return false;
        } else {
            return true;
        }
    }
    public byte[] readIv() {
        String selectQuery = "SELECT IV FROM " + TABLE_NAME + " WHERE ID "  + " = '" + 1 +"'";
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(selectQuery, null);
        cursor.moveToFirst();
        byte [] iv = cursor.getBlob(0);
        return iv;

    }
    // encrypting note
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private byte[] encrypt(byte[] strToEncrypt)
    {
        try {

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, getTheKey());
            byte[] iv = cipher.getIV();
            insertIV(iv);
            byte[] encryptByte = cipher.doFinal(strToEncrypt);

            return encryptByte;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String showContent(){
        String selectQuery = "SELECT CONTENT FROM " + TABLE_NAME + " WHERE ID "  + " = '" + 1 +"'";
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(selectQuery, null);
        cursor.moveToFirst();
        String dcrypt;
        byte cont [] = fromBase64(cursor.getString(0));
        dcrypt = decrypt(cont);
        return dcrypt;
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public String decrypt(byte[] strToDecrypt)
    {
        try {
            byte[] decryptedBytes;

            final Cipher mCipher = Cipher.getInstance("AES/GCM/NoPadding");
            final GCMParameterSpec spec = new GCMParameterSpec(IV_SIZE*8, readIv());
            mCipher.init(Cipher.DECRYPT_MODE,getTheKey(), spec);
            decryptedBytes = mCipher.doFinal(strToDecrypt);

            String Result = new String(decryptedBytes,"UTF-8");

            return Result;

        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (AEADBadTagException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] fromBase64(String hex) {

        return Base64.decode(hex, Base64.DEFAULT);
    }

    private static String toBase64(byte[] array) {

        return Base64.encodeToString(array, Base64.DEFAULT);
    }
}
