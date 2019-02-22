
-skipnonpubliclibraryclasses
-injars target/ASGW-fat.jar
-outjars target/ASGW-fat-pg.jar
-libraryjars <java.home>/lib/rt.jar
-printmapping ASGW.map

-dontwarn
#-dontoptimize
-repackageclasses ''
-allowaccessmodification

-keepattributes InnerClasses,EnclosingMethod
-keepattributes Signature
-keepattributes *Annotation*

-keep public class com.additionsecurity.App {
	public static void main(java.lang.String[]);
}

-keep public class com.additionsecurity.AppVerticle {
	public void start();
}

#-keeppackagenames io.vertx.core.**
#-keep class io.vertx.core.spi.**
#-keep class io.vertx.core**.impl.**
#-keepclasseswithmembers class io.netty.**

-keepnames class com.fasterxml.jackson.** { 
	*;
}

-keepclassmembers,allowoptimization enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

-keepclassmembers class io.netty.util.internal.chmv8.Striped64 {
	*;
}

-keep class io.vertx.core.spi.BufferFactory
-keep class io.vertx.core.spi.FutureFactory
-keep class io.vertx.core.spi.launcher.CommandFactory
-keep class io.vertx.core.spi.PumpFactory
-keep class io.vertx.core.spi.VertxFactory
-keep class io.vertx.core.spi.WebSocketFrameFactory
-keep class com.fasterxml.jackson.core.JsonFactory
-keep class com.fasterxml.jackson.core.ObjectCodec
-keep class io.vertx.core.impl.VertxFactoryImpl
-keep class io.vertx.core.impl.FutureFactoryImpl
-keep class io.vertx.core.buffer.impl.BufferFactoryImpl
