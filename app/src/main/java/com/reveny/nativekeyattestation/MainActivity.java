package com.reveny.nativekeyattestation;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

public class MainActivity extends AppCompatActivity {
    public native String getAttestationResult();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        System.loadLibrary("Attestation");

        TextView view = findViewById(R.id.result_text);
        String result = getAttestationResult();
        view.setText(result);
    }
}