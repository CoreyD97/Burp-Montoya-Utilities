import java.lang.reflect.Method;

public class TestExtension {
    public static void main(String[] args) {
        System.out.println("Loading extension as legacy extension...");

        try {
            Method main = Class.forName("burp.StartBurp").getMethod("main", String[].class);
            main.invoke(null, (Object) args);
        }catch (Exception e){
            System.err.println("Cannot start burp. Check the burp jar is correctly included in the classpath.");
        }
    }
}
