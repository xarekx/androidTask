package com.example.szef.zadaniebsm;

import android.annotation.TargetApi;
import android.content.Intent;
import android.hardware.fingerprint.FingerprintManager;
import android.hardware.fingerprint.FingerprintManager.AuthenticationCallback;
import android.os.Build;
import android.widget.Toast;

@TargetApi(Build.VERSION_CODES.M)
class AuthenticationHandler extends AuthenticationCallback {

    private MainActivity mainActivity;
    public AuthenticationHandler(MainActivity mainActivity) {
        this.mainActivity = mainActivity;
    }

    @Override
    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
        super.onAuthenticationSucceeded(result);
        Toast.makeText(mainActivity, "Auth Success", Toast.LENGTH_SHORT).show();
        mainActivity.startActivity(new Intent(mainActivity,notepad.class));

    }

    @Override
    public void onAuthenticationFailed() {
        super.onAuthenticationFailed();
        Toast.makeText(mainActivity, "Auth Failed", Toast.LENGTH_SHORT).show();
    }
}
