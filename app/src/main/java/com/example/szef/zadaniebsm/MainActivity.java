package com.example.szef.zadaniebsm;


import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.Intent;

import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import android.support.annotation.RequiresApi;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


public class MainActivity extends AppCompatActivity {


    private KeyStore keyStore;
    private static final String KEY_NAME="EDMTDev";
    private Cipher cipher;
    KeyGenerator keyGenerator;

    private Button approve;
    private EditText password;
    public EditText createPassword;
    private Button btnCreatePassword;
    public String myPass;
    dataBaseHelper myDB;


    @TargetApi(Build.VERSION_CODES.M)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnCreatePassword = (Button)findViewById(R.id.btnCreatePassword);
        approve = (Button)findViewById(R.id.btnApprove);

        password = (EditText)findViewById(R.id.textPassword);
        createPassword = (EditText)findViewById(R.id.createPassword);

        try {
            myDB = new dataBaseHelper(this);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            myDB.createKeyStore();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

        addPassword();
        Login();
        FingerPrint();

        KeyguardManager keyguardManager = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager)getSystemService(FINGERPRINT_SERVICE);

    }

    @TargetApi(Build.VERSION_CODES.M)
    public void FingerPrint() {
        KeyguardManager keyguardManager = (KeyguardManager)getSystemService(KEYGUARD_SERVICE);
        FingerprintManager fingerprintManager = (FingerprintManager)getSystemService(FINGERPRINT_SERVICE);
        if(!Objects.requireNonNull(fingerprintManager).isHardwareDetected()) {
            Log.e("Hardware","Finger print hardware not detected");
            Toast.makeText(this, "FingerPrint not available", Toast.LENGTH_SHORT).show();
            return;
        }

        if (ActivityCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            return;
        }

        if(!Objects.requireNonNull(keyguardManager).isKeyguardSecure()) {
            Toast.makeText(this, "Lock screen", Toast.LENGTH_SHORT).show();
        }

        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
        }
        catch(Exception e) {
            Log.e("Keystore",e.getMessage());
            return;
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        }
        catch(Exception e ) {
            Log.e("KeyGenerator",e.getMessage());
        }

        try {
            keyStore.load(null);
            keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();
        }
        catch(Exception e) {
            Log.e("Generating keys",e.getMessage());
            return;
        }
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        }
        catch(Exception e) {
            Log.e("Cipher",e.getMessage());
            return;
        }

        try {
            keyStore.load(null);
            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME, null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
        }
        catch(Exception e) {
            Log.e("Secret Key",e.getMessage());
            return;
        }

        FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

        CancellationSignal cancellationSignal = new CancellationSignal();
        fingerprintManager.authenticate(cryptoObject,cancellationSignal,0,new AuthenticationHandler(this),null);
    }



    public void addPassword() {
        btnCreatePassword.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                myPass = createPassword.getText().toString();
                Boolean checkPass = null;
                if (myPass.length() < 7) {
                    Toast.makeText(MainActivity.this, "Password is too short", Toast.LENGTH_SHORT).show();
                } else {
                    try {
                        checkPass = myDB.checkPassword(myPass);
                    } catch (NoSuchAlgorithmException e) {
                        e.printStackTrace();
                    }
                    if (!checkPass) {
                        Toast.makeText(MainActivity.this, "Password exist", Toast.LENGTH_SHORT).show();
                    } else {
                        try {
                            myDB.insertBsm(myPass);
                            Toast.makeText(MainActivity.this, "Password created", Toast.LENGTH_LONG).show();
                            btnCreatePassword.setEnabled(false);
                            approve.setEnabled(true);
                        } catch (NoSuchAlgorithmException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }

        });
    }
    public void Login() {
        approve.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.KITKAT)
            @Override
            public void onClick(View v) {
                Boolean checkPassword = null;
                try {
                    checkPassword = myDB.checkPassword(password.getText().toString());
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                if(!checkPassword) {
                    Toast.makeText(MainActivity.this,"Password correct",Toast.LENGTH_LONG).show();
                    Intent intent = new Intent(MainActivity.this,notepad.class);
                    startActivity(intent);
                } else {
                    approve.setEnabled(false);
                    Toast.makeText(MainActivity.this,"Wrong Password",Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    public static String md5(String salt, String plainText)
            throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("MD5");
        if (salt != null) {
            md.update(salt.getBytes());
        }
        md.update(plainText.getBytes());
        byte byteData[] = md.digest();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < byteData.length; i++) {
            sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
        return sb.toString();
    }

    @Override
    protected void onResume() {
        super.onResume();
        FingerPrint();
    }
}
