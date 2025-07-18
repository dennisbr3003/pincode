package com.dennis_brink.android.mypincode;

import android.app.Application;
import android.content.Context;

public class ThisApplication extends Application  {

    private static ThisApplication instance;

    @Override
    public void onCreate() {
        super.onCreate();
        instance = this;
    }

    public static Context getAppContext() {
        return instance.getApplicationContext();
    }

}
