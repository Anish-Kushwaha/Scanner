package com.anishkushwaha.scanner;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.os.Bundle;
import android.view.View;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebResourceError;
import android.widget.FrameLayout;
import android.widget.LinearLayout;
import android.widget.TextView;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.content.Intent;
import android.net.Uri;
import android.view.Gravity;
import android.view.Window;
import android.view.WindowManager;

public class MainActivity extends Activity {
    private static final String APP_URL = "https://scanner-rose-rho.vercel.app/login.html";
    private static final int FILE_CHOOSER_REQUEST = 7401;
    private android.webkit.ValueCallback<Uri[]> uploadCallback;
    private WebView webView;
    private LinearLayout errorPanel;

    @SuppressLint("SetJavaScriptEnabled")
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().setStatusBarColor(Color.rgb(5, 12, 28));
        getWindow().setNavigationBarColor(Color.rgb(5, 12, 28));
        getWindow().getDecorView().setSystemUiVisibility(0);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.rgb(5, 12, 28));

        webView = new WebView(this);
        WebSettings settings = webView.getSettings();
        settings.setJavaScriptEnabled(true);
        settings.setDomStorageEnabled(true);
        settings.setDatabaseEnabled(false);
        settings.setAllowFileAccess(false);
        settings.setAllowContentAccess(false);
        settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);
        settings.setJavaScriptCanOpenWindowsAutomatically(false);
        settings.setSupportMultipleWindows(false);
        settings.setMediaPlaybackRequiresUserGesture(true);
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            settings.setSafeBrowsingEnabled(true);
        }
        settings.setUserAgentString(settings.getUserAgentString() + " ScannerAndroid/1.0");
        webView.setBackgroundColor(Color.rgb(5, 12, 28));
        webView.setOverScrollMode(View.OVER_SCROLL_NEVER);
        webView.setWebChromeClient(new WebChromeClient() {
            @Override public boolean onShowFileChooser(WebView view,
                    android.webkit.ValueCallback<Uri[]> filePathCallback,
                    FileChooserParams fileChooserParams) {
                if (uploadCallback != null) uploadCallback.onReceiveValue(null);
                uploadCallback = filePathCallback;
                try {
                    Intent intent = fileChooserParams.createIntent();
                    startActivityForResult(intent, FILE_CHOOSER_REQUEST);
                    return true;
                } catch (Exception error) {
                    uploadCallback = null;
                    return false;
                }
            }
        });
        webView.setWebViewClient(new WebViewClient() {
            @Override public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest request) {
                Uri uri = request.getUrl();
                String host = uri.getHost() == null ? "" : uri.getHost();
                if ("scanner-lbpki7lh7-anish-kushwahas-projects-bc957f54.vercel.app".equalsIgnoreCase(host)
                        || "scanner-rose-rho.vercel.app".equalsIgnoreCase(host)
                        || "scanner-anish-kushwahas-projects-bc957f54.vercel.app".equalsIgnoreCase(host)
                        || "scanner-git-main-anish-kushwahas-projects-bc957f54.vercel.app".equalsIgnoreCase(host)) return false;
                if ("https".equalsIgnoreCase(uri.getScheme())) {
                    try {
                        startActivity(new Intent(Intent.ACTION_VIEW, uri));
                    } catch (android.content.ActivityNotFoundException ignored) {
                        showError();
                    }
                    return true;
                }
                return true;
            }
            @Override public void onReceivedError(WebView view, WebResourceRequest request, WebResourceError error) {
                if (request.isForMainFrame()) showError();
            }
            @Override public void onReceivedHttpError(WebView view, WebResourceRequest request, android.webkit.WebResourceResponse response) {
                if (request.isForMainFrame() && response.getStatusCode() >= 400) showError();
            }
            @Override public void onPageFinished(WebView view, String url) {
                if (errorPanel != null && !errorPanel.isShown() && view.getVisibility() != View.GONE) {
                    errorPanel.setVisibility(View.GONE);
                    webView.setVisibility(View.VISIBLE);
                }
            }
        });

        errorPanel = buildErrorPanel();
        root.addView(webView, new FrameLayout.LayoutParams(-1, -1));
        root.addView(errorPanel, new FrameLayout.LayoutParams(-1, -1));
        setContentView(root);

        if (state == null) webView.loadUrl(APP_URL);
        else webView.restoreState(state);
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        if (requestCode == FILE_CHOOSER_REQUEST) {
            if (uploadCallback != null) {
                Uri[] results = WebChromeClient.FileChooserParams.parseResult(resultCode, data);
                uploadCallback.onReceiveValue(results);
                uploadCallback = null;
            }
            return;
        }
        super.onActivityResult(requestCode, resultCode, data);
    }

    private LinearLayout buildErrorPanel() {
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setGravity(Gravity.CENTER);
        panel.setPadding(36, 32, 36, 32);
        panel.setBackgroundColor(Color.rgb(5, 12, 28));
        TextView title = new TextView(this);
        title.setText("Connection unavailable");
        title.setTextColor(Color.WHITE);
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        TextView body = new TextView(this);
        body.setText("Scanner could not reach its secure service. Check your internet connection and try again.");
        body.setTextColor(Color.rgb(164, 181, 205));
        body.setTextSize(15);
        body.setGravity(Gravity.CENTER);
        body.setPadding(0, 14, 0, 22);
        TextView retry = new TextView(this);
        retry.setText("TRY AGAIN");
        retry.setTextColor(Color.rgb(5, 12, 28));
        retry.setTextSize(14);
        retry.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        retry.setGravity(Gravity.CENTER);
        retry.setPadding(28, 15, 28, 15);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(Color.rgb(0, 210, 240));
        bg.setCornerRadius(24);
        retry.setBackground(bg);
        retry.setOnClickListener(v -> {
            panel.setVisibility(View.GONE);
            webView.setVisibility(View.VISIBLE);
            webView.loadUrl(APP_URL);
        });
        panel.addView(title);
        panel.addView(body);
        panel.addView(retry);
        panel.setVisibility(View.GONE);
        return panel;
    }

    private void showError() {
        if (webView != null) webView.setVisibility(View.GONE);
        if (errorPanel != null) errorPanel.setVisibility(View.VISIBLE);
    }

    @Override public void onBackPressed() {
        if (webView != null && webView.canGoBack()) webView.goBack();
        else super.onBackPressed();
    }

    @Override protected void onSaveInstanceState(Bundle out) {
        if (webView != null) webView.saveState(out);
        super.onSaveInstanceState(out);
    }

    @Override protected void onDestroy() {
        if (uploadCallback != null) {
            uploadCallback.onReceiveValue(null);
            uploadCallback = null;
        }
        if (webView != null) {
            webView.stopLoading();
            webView.removeAllViews();
            webView.destroy();
        }
        super.onDestroy();
    }
}
