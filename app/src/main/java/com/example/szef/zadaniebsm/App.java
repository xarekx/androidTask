package com.example.szef.zadaniebsm;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.Application;
import android.app.KeyguardManager;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v4.app.ActivityCompat;
import android.util.Log;
import android.widget.Toast;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Objects;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class App extends Application {
    @Override
    public void onCreate() {
        super.onCreate();
    }
    }


