package com.dennis_brink.android.mypincode;

import static android.content.res.Configuration.UI_MODE_NIGHT_MASK;
import static android.content.res.Configuration.UI_MODE_NIGHT_NO;
import static android.content.res.Configuration.UI_MODE_NIGHT_UNDEFINED;
import static android.content.res.Configuration.UI_MODE_NIGHT_YES;

import android.graphics.drawable.ColorDrawable;
import android.graphics.drawable.Drawable;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.ShapeDrawable;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.Button;
import android.widget.ImageButton;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;

public class PinActivity extends AppCompatActivity {

    Button btn1, btn2, btn3, btn4, btn5, btn6, btn7, btn8, btn9, btn0;
    ImageButton imgBtn1,imgBtn2,imgBtn3,imgBtn4,imgBtn5, imgBtnOk, imgBtnBck;
    Configuration config;
    int nightModeFlags;
    TextView txtHint;
    String pinCode="", pinCodeConfirm="", savedPinCode="";
    private static final String TAG = "DENNIS_B";

    Encryption encryption = new Encryption();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_pin);

        txtHint = findViewById(R.id.txtViewHint);

        config = FileHelper.readData(PinActivity.this);

        if (config.getPinCode().equals("")){
            Log.d(TAG, "No pin yet. Ask for a pin");
            txtHint.setTextColor(getColor(R.color.OrangeRed));
            txtHint.setText(R.string._no_pin_yet);
        } else {
            Log.d(TAG, "Pin is available " + config.getPinCode());
            savedPinCode = encryption.decrypt(config.getPinCode());
            txtHint.setTextColor(getColor(R.color.DimGray));
        }

        pinCode = "";
        imgBtn1 = findViewById(R.id.imageButtonPin1);
        imgBtn2 = findViewById(R.id.imageButtonPin2);
        imgBtn3 = findViewById(R.id.imageButtonPin3);
        imgBtn4 = findViewById(R.id.imageButtonPin4);
        imgBtn5 = findViewById(R.id.imageButtonPin5);

        btn1 = findViewById(R.id.btn1);
        btn1.setOnClickListener(view -> processClick(view));
        btn2 = findViewById(R.id.btn2);
        btn2.setOnClickListener(view -> processClick(view));
        btn3 = findViewById(R.id.btn3);
        btn3.setOnClickListener(view -> processClick(view));
        btn4 = findViewById(R.id.btn4);
        btn4.setOnClickListener(view -> processClick(view));
        btn5 = findViewById(R.id.btn5);
        btn5.setOnClickListener(view -> processClick(view));
        btn6 = findViewById(R.id.btn6);
        btn6.setOnClickListener(view -> processClick(view));
        btn7 = findViewById(R.id.btn7);
        btn7.setOnClickListener(view -> processClick(view));
        btn8 = findViewById(R.id.btn8);
        btn8.setOnClickListener(view -> processClick(view));
        btn9 = findViewById(R.id.btn9);
        btn9.setOnClickListener(view -> processClick(view));
        btn0 = findViewById(R.id.btn0);
        btn0.setOnClickListener(view -> processClick(view));

        imgBtnBck = findViewById(R.id.imageButtonBck);
        imgBtnBck.setOnClickListener(view -> processClick(view));
        imgBtnOk = findViewById(R.id.imageButtonOk);
        imgBtnOk.setOnClickListener(view -> processClick(view));
        imgBtnOk.setClickable(false);

        setupTheme(); // day and night colors

    }

    private void setupTheme() {

        nightModeFlags = getApplicationContext().getResources().getConfiguration().uiMode & UI_MODE_NIGHT_MASK;

        switch (nightModeFlags) {
            case UI_MODE_NIGHT_YES:
                Log.d(TAG, "UI_MODE_NIGHT_YES");
                setupNightMode();
                break;
            case UI_MODE_NIGHT_NO:
                Log.d(TAG, "UI_MODE_NIGHT_NO");
                break;
            case UI_MODE_NIGHT_UNDEFINED:
                Log.d(TAG, "UI_MODE_NIGHT_UNDEFINED");
                break;
        }

    }

    private void setupNightMode() {

        btn1.setTextColor(getColor(R.color.white));
        btn2.setTextColor(getColor(R.color.white));
        btn3.setTextColor(getColor(R.color.white));
        btn4.setTextColor(getColor(R.color.white));
        btn5.setTextColor(getColor(R.color.white));
        btn6.setTextColor(getColor(R.color.white));
        btn7.setTextColor(getColor(R.color.white));
        btn8.setTextColor(getColor(R.color.white));
        btn9.setTextColor(getColor(R.color.white));
        btn0.setTextColor(getColor(R.color.white));

        setupSpecialButtons("normal");

    }

    private void setupSpecialButtons(String state){
        if(state.equals("normal")) {
            if(nightModeFlags == UI_MODE_NIGHT_YES){
                imgBtnBck.setImageDrawable(getDrawable(R.drawable.arrow_back_45_night));
                imgBtnOk.setImageDrawable(getDrawable(R.drawable.check_45_night));
            } else {
                imgBtnBck.setImageDrawable(getDrawable(R.drawable.arrow_back_45));
                imgBtnOk.setImageDrawable(getDrawable(R.drawable.check_45));
            }
        } else { // color change, ok button goes to green
            if(nightModeFlags == UI_MODE_NIGHT_YES){
                imgBtnBck.setImageDrawable(getDrawable(R.drawable.arrow_back_45_night));
                imgBtnOk.setImageDrawable(getDrawable(R.drawable.check_45_ok));
            } else {
                imgBtnBck.setImageDrawable(getDrawable(R.drawable.arrow_back_45));
                imgBtnOk.setImageDrawable(getDrawable(R.drawable.check_45_ok));
            }
        }
    }

    @Override
    public void onBackPressed() {
        super.onBackPressed();
        finish();
    }

    private void processClick(View view){

        if(!(view.getTag().equals("x") || view.getTag().equals("z"))){
            // it's a digit, we need to know which one
            if(pinCode.length() == 5){ // done
                return;
            }
            pinCode += String.valueOf(view.getTag());

            switch(pinCode.length()){
                case 1:
                    setPinNumberCircleDrawableColor(imgBtn1, R.color.light_grey);
                    break;
                case 2:
                    setPinNumberCircleDrawableColor(imgBtn2, R.color.light_grey);
                    Animation animationFadeOut = AnimationUtils.loadAnimation(getApplicationContext(), R.anim.fade_out);
                    txtHint.startAnimation(animationFadeOut);
                    animationFadeOut.setAnimationListener(new Animation.AnimationListener() {
                        @Override
                        public void onAnimationStart(Animation animation) {}

                        @Override
                        public void onAnimationEnd(Animation animation) {txtHint.setVisibility(View.INVISIBLE);}

                        @Override
                        public void onAnimationRepeat(Animation animation) {}
                    });
                    break;
                case 3:
                    setPinNumberCircleDrawableColor(imgBtn3, R.color.light_grey);
                    break;
                case 4:
                    setPinNumberCircleDrawableColor(imgBtn4, R.color.light_grey);
                    break;
                case 5:
                    setPinNumberCircleDrawableColor(imgBtn5, R.color.light_grey);
                    setupSpecialButtons("ok");
                    imgBtnOk.setClickable(true);
                    break;
            }

        } else { // function button (back or ok)
            if(view.getTag().equals("x")){ // back button pressed

                imgBtnOk.setClickable(false); // always less than five
                setupSpecialButtons("normal");

                if (pinCode.length() == 0) {
                    return;
                }

                pinCode = pinCode.substring(0, pinCode.length() - 1);

                switch(pinCode.length() + 1){
                    case 1:
                        setPinNumberCircleDrawableColor(imgBtn1, R.color.transparant);
                        break;
                    case 2:
                        setPinNumberCircleDrawableColor(imgBtn2, R.color.transparant);
                        Animation animationFadeIn = AnimationUtils.loadAnimation(getApplicationContext(), R.anim.fade_in);
                        txtHint.startAnimation(animationFadeIn);
                        animationFadeIn.setAnimationListener(new Animation.AnimationListener() {
                            @Override
                            public void onAnimationStart(Animation animation) {}

                            @Override
                            public void onAnimationEnd(Animation animation) {txtHint.setVisibility(View.VISIBLE);}

                            @Override
                            public void onAnimationRepeat(Animation animation) {}
                        });
                        break;
                    case 3:
                        setPinNumberCircleDrawableColor(imgBtn3, R.color.transparant);
                        break;
                    case 4:
                        setPinNumberCircleDrawableColor(imgBtn4, R.color.transparant);
                        break;
                    case 5:
                        setPinNumberCircleDrawableColor(imgBtn5, R.color.transparant);
                        break;
                }
            } else {  // ok, check the pincode here
                // first check if we have a saved pincode. If we don't we ask confirmation
                try {

                    if (savedPinCode.isEmpty() && pinCodeConfirm.isEmpty()) {

                        pinCodeConfirm = pinCode;
                        txtHint.setVisibility(View.VISIBLE);
                        txtHint.setText(R.string._pin_confirm);

                        resetPin();

                        return;

                    } else if (savedPinCode.isEmpty() && !pinCodeConfirm.isEmpty()) {
                        if (pinCode.equals(pinCodeConfirm)) {
                            txtHint.setText(R.string._empty);
                            config.setPinCode(encryption.encrypt(pinCode));
                            FileHelper.writeData(config, this);
                            Log.d(TAG, "User pincode matches confirmation pincode - pincode accepted");
                            runMainActivity();
                        } else {
                            // confirm again. pincodes do not match
                            txtHint.setVisibility(View.VISIBLE);
                            txtHint.setText(R.string._pin_not_match);

                            resetPin();

                            return;
                        }
                    } else if (pinCode.equals(savedPinCode) && !pinCode.isEmpty() && !savedPinCode.isEmpty()) {
                        txtHint.setText(R.string._empty);
                        Log.d(TAG, "User pincode matches saved pincode --> access granted");
                        runMainActivity();
                    } else {
                        txtHint.setVisibility(View.VISIBLE);
                        txtHint.setTextColor(getColor(R.color.OrangeRed));
                        txtHint.setText(R.string._pin_incorrect);

                        resetPin();

                        return;
                    }
                }catch(Exception e){
                    Log.d(TAG, "Error " + e.getLocalizedMessage());
                }
            }

        }
    }

    private void resetPin(){

        pinCode = "";

        setPinNumberCircleDrawableColor(imgBtn1, R.color.transparant);
        setPinNumberCircleDrawableColor(imgBtn2, R.color.transparant);
        setPinNumberCircleDrawableColor(imgBtn3, R.color.transparant);
        setPinNumberCircleDrawableColor(imgBtn4, R.color.transparant);
        setPinNumberCircleDrawableColor(imgBtn5, R.color.transparant);

        imgBtnOk.setClickable(false); // always less than five
        setupSpecialButtons("normal");

    }

    private void runMainActivity(){
        resetPin();
        Log.d(TAG, "run activity here");
    }

    private void setPinNumberCircleDrawableColor(ImageButton button, int color) {

        Drawable background = button.getBackground();
        if (background instanceof ShapeDrawable) {
            // cast to 'ShapeDrawable'
            ShapeDrawable shapeDrawable = (ShapeDrawable) background;
            shapeDrawable.getPaint().setColor(ContextCompat.getColor(getApplicationContext(), color));
        } else if (background instanceof GradientDrawable) {
            // cast to 'GradientDrawable'
            GradientDrawable gradientDrawable = (GradientDrawable) background;
            gradientDrawable.setColor(ContextCompat.getColor(getApplicationContext(), color));
        } else if (background instanceof ColorDrawable) {
            // alpha value may need to be set again after this call
            ColorDrawable colorDrawable = (ColorDrawable) background;
            colorDrawable.setColor(ContextCompat.getColor(getApplicationContext(), color));
        } else {
            Log.d(TAG, "Background drawable type: unknown. Background color could not be set.");
        }

    }
}