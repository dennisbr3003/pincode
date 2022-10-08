package com.dennis_brink.android.mypincode;

import java.io.Serializable;

public class Configuration implements Serializable {

    private String pinCode;

    public Configuration(String pinCode) {
        this.pinCode = pinCode;
    }

    public String getPinCode() {
        return pinCode;
    }

    public void setPinCode(String pinCode) {
        this.pinCode = pinCode;
    }

    @Override
    public String toString() {
        return "Configuration{" +
                "pinCode='" + pinCode + '\'' +
                '}';
    }
}
