package com.dennis_brink.android.mypincode;

import android.content.Context;
import android.util.Log;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;

public class FileHelper {

    public static final String FILENAME = "config.dat";

    public static void writeData(Configuration config, Context context){
        try {
            FileOutputStream fos = context.openFileOutput(FILENAME, context.MODE_PRIVATE);
            ObjectOutputStream oas = new ObjectOutputStream(fos);
            oas.writeObject(config);
            oas.close();
        } catch (FileNotFoundException e) {
            logError(e);
        } catch (IOException e) {
            logError(e);
        }
    }

    public static Configuration readData (Context context){
        Configuration config = null;
        try {
            FileInputStream fis = context.openFileInput(FILENAME);
            ObjectInputStream ois = new ObjectInputStream(fis);
            config = (Configuration) ois.readObject();
        } catch (FileNotFoundException e) {
            // let's not return null here. The first time the app is run
            // there will be no data file and no entries. This will cause
            // this exception and the return of a null object (X)
            config = new Configuration("");
            logError(e);
        } catch (IOException e) {
            logError(e);
        } catch (ClassNotFoundException e) {
            logError(e);
        }
        return config;
    }

    private static void logError(Exception e){
        Log.d("DENNIS_B", e.getMessage());
    }
}
