package com.qwadb.app

import android.app.Application
import com.qwadb.app.adb.AdbIdentityManager
import com.qwadb.app.diagnostics.DiagnosticLogger
import timber.log.Timber

class AdbManagerApplication : Application() {
    override fun onCreate() {
        super.onCreate()

        DiagnosticLogger.initialize(this)
        AdbIdentityManager.initialize(this)
        AppServices.initialize(this)

        if (BuildConfig.DEBUG) {
            Timber.plant(Timber.DebugTree())
        }
    }
}
