# Keep Moshi/Retrofit model classes used reflectively.
-keep class com.reconx.sentinel.feature.reconx.** { *; }
-keepclassmembers class * { @com.squareup.moshi.Json <fields>; }
-dontwarn okhttp3.**
-dontwarn retrofit2.**
