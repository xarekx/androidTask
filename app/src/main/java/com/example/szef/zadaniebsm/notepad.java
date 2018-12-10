package com.example.szef.zadaniebsm;


import android.annotation.TargetApi;
import android.content.Intent;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;


import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Arrays;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;


public class notepad extends AppCompatActivity {

    dataBaseHelper myDB;
    Button btnChangePassword;
    Button noteButton;
    EditText editPassword;
    EditText editPassword2;
    EditText note;
    public String myPass1;
    public String myPass2;
    Button showCont;

    @TargetApi(Build.VERSION_CODES.M)
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_notepad);

        btnChangePassword = findViewById(R.id.btnChangePassword);
        editPassword = findViewById(R.id.editPassword);
        editPassword2 = findViewById(R.id.editPassword2);
        noteButton = findViewById(R.id.noteButton);
        note = findViewById(R.id.editText);
        showCont = findViewById(R.id.showCont);


        try {
            myDB = new dataBaseHelper(this);
            note.setText(myDB.showContent());
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
        btnChangePassword.setOnClickListener(v -> changePass());
        showCont.setOnClickListener(v -> {
            try {
                showNote();
            } catch (Exception e) {
                e.printStackTrace();
            }
        });

        noteButton.setOnClickListener(v -> note());
        try {
            myDB.createKeyStore();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }

    }
    public void changePass() {
        btnChangePassword.setOnClickListener(v -> {
            myPass1 = editPassword.getText().toString();
            myPass2 = editPassword2.getText().toString();
            Boolean changing = null;
            if(myPass2.length()<7) {
                Toast.makeText(notepad.this, "password too short", Toast.LENGTH_SHORT).show();
            } else {
                try {
                    changing = myDB.change(myPass1, myPass2);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
                if(!changing) {
                    Toast.makeText(notepad.this,"Password changed",Toast.LENGTH_LONG).show();
                } else {
                    Toast.makeText(notepad.this,"Failed changing",Toast.LENGTH_LONG).show();
                }
            }
        });
    }
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void note() {
                try {
                    if(myDB.insertContent(note.getText().toString())) {
                        note.setText("");
                        Toast.makeText(notepad.this,"Messages saved", Toast.LENGTH_LONG).show();
                    } else {
                        Toast.makeText(notepad.this, "Error", Toast.LENGTH_SHORT).show();
                    }
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
                } catch (Exception e) {
                    e.printStackTrace();
                }

    }
    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    public void showNote() throws NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException, KeyStoreException, IOException {
        dataBaseHelper nowy;
        nowy = new dataBaseHelper(this);
        if(note== null) {
            note.setText("");
        }
        if(note!=null) {
            note.setText(nowy.showContent());
        }
    }

}
