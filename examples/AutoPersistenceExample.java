import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.nameManager.NameCollisionException;
import com.coreyd97.BurpExtenderUtilities.PersistedList;
import com.coreyd97.BurpExtenderUtilities.PersistedMap;
import com.coreyd97.BurpExtenderUtilities.PersistedObject;
import com.coreyd97.BurpExtenderUtilities.PersistedSet;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import com.google.gson.reflect.TypeToken;

import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.border.EmptyBorder;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.lang.reflect.Field;
import java.lang.reflect.Type;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;

public class AutoPersistenceExample implements BurpExtension{
  @Override
  public void initialize(MontoyaApi api){
    ///////////////////////////////////////////
    // INSTANTIATING AUTO-PERSISTING OBJECTS //
    ///////////////////////////////////////////
    PersistedSet<Path> minimalPathSet = new PersistedSet<>(
      api, "minimalPathSet", Preferences.Visibility.VOLATILE
    );

    //specify a default value
    PersistedSet<String> set = new PersistedSet<>(
      api, "testSet", Preferences.Visibility.PROJECT,
      new HashSet<>()
    );

    //specify a default value and the type to serialize/deserialize as
    PersistedSet<String> oldSet = new PersistedSet<>(
      api, "oldSet", Preferences.Visibility.PROJECT,
      new TypeToken<HashSet<String>>(){}, new HashSet<>()
    );
    //oldSet.save();

    //specify the type without a default value
    PersistedList<String> lst = new PersistedList<>(
      api, "testLst", Preferences.Visibility.PROJECT,
      new ArrayList<>()
    );

    //specify a default without a type
    PersistedMap<String, String, HashMap<String, String>> map = new PersistedMap<>(
      api, "testMap", Preferences.Visibility.PROJECT,
      new HashMap<>()
    );

    //Create a PersistedObject
    String persistedName = "settings2";
    api.logging().logToOutput("persisted settings2 b4 instantiation = " + api.persistence().extensionData().getString(persistedName));
    //api.persistence().extensionData().deleteString(persistedName);
    Settings2 settings = new Settings2(api, persistedName, Preferences.Visibility.PROJECT);
    try{
      Settings2 badSettings =
        new Settings2(api, persistedName, Preferences.Visibility.PROJECT);
    }
    catch(NameCollisionException e){
      api.logging().logToOutput("badSettings failed to initialize (that means collision detection is working)");
    }
    api.logging().logToOutput("\npersisted settings2 aftr instantiation = " + api.persistence().extensionData().getString(persistedName));

    ///////////////////////////////////
    // USING AUTO-PERSISTING OBJECTS //
    ///////////////////////////////////
    //note: the auto-persisting collections are intended to work
    //  without the user needing to create any custom implementations
    //minimalPathSet.contains(Path.of("/etc/passwd")); //will fail because no default was passed in... so minimalPathSet is null
    minimalPathSet.set(new HashSet<>());//required since no default is null
    minimalPathSet.add(Path.of("/some/path")); //used like a normal set... but automatically persists
    //list and map can be used similarly
    lst.add("test");//used normal but auto-persists

    for(String str : lst){
      //and modifications in the loop must use an explicit call to `save()`
      str += "something";
      lst.save();
    }

    //PersistedObjects are similar but require the user to create a custom implementation
    //  (because there is no way for us to know in advance what fields the user wants to persist)
    //note: This is just an example. If you prefer getters to start with the word "get"
    //  and your setters to start with the word "set"... you can do that.
    //  The implementation of the class that extends `PersistedObject` is left up to the users of the library
    settings.activeEnabled();//get value
    settings.activeEnabled(false);//set value (auto-persists based on user-defined implementation)
    settings.inFilePaths().add(Path.of("/test/path"));//will NOT auto-persist
    settings.save();//required to persist change from previous line
    settings.addInFile(Path.of("/test/path/2"));//WILL auto-persist based on user-defined implementation

    List<Path> inFilePaths = settings.inFilePaths();
    for(Path path : inFilePaths){
      //modifications to inFilePaths are generally unsafe here
      //  but even if using a ConcurrentList or something like that...
      //  modifications will DEFINITELY not be auto-persisted
      settings.save();
    }

    api.logging().logToOutput("\nsettings2 = " + settings.toString());
    api.logging().logToOutput("\npersisted settings2 = " + api.persistence().extensionData().getString(persistedName));

    //////////////////////////////////
    // MULTI-LEVEL PERSISTED OBJECT //
    //////////////////////////////////
    final boolean CLEAN = false;
    final boolean RESET = false;
    api.logging().logToOutput(api.persistence().extensionData().getString("extensionSettings"));
    if(CLEAN) api.persistence().extensionData().deleteString("extensionSettings");

    ExtensionSettings extSettings = new ExtensionSettings(api, "extensionSettings", Preferences.Visibility.PROJECT);
    if(CLEAN){
      extSettings.unpersist();
      extSettings.repersist();
    }
    api.logging().logToError("extSettings = \n" + extSettings);
    boolean subSettings1Enabled = extSettings.subSettings1().enabled();
    extSettings.subSettings1().enabled(!subSettings1Enabled);
    api.logging().logToError("\n\nextSettings = \n" + extSettings);

    if(RESET){
      extSettings.reset();
      api.logging().logToError("\n\nextSettings = \n" + extSettings);
    }

    /////////////////
    // NAMESPACING //
    /////////////////
    GsonProvider gsonProvider = new GsonProvider();
    gsonProvider.registerTypeHierarchyAdapter(
      Path.class, new JsonSerializer<Path>(){
        @Override
        public JsonElement serialize(
          Path path, Type type, JsonSerializationContext context
        ){
          return new JsonPrimitive("namespaceTestSerializationWorked");
        }
      }
    );

    api.logging().logToOutput("\n\npersisted namespaceTest b4 instantiation = " + api.persistence().preferences().getString("namespaceTest"));
    api.logging().logToOutput("\npersisted .namespaceTest b4 instantiation = " + api.persistence().preferences().getString(".namespaceTest"));
    api.logging().logToOutput("\npersisted MainExtensionNamespace.namespaceTest b4 instantiation = " + api.persistence().preferences().getString("MainExtensionNamespace.namespaceTest"));

    PersistedList<Path> namespaceTest = new PersistedList<>(
      api, "namespaceTest", Preferences.Visibility.GLOBAL,
      gsonProvider,
      new TypeToken<List<Path>>(){}, List.of(Path.of("/namespace/test")),
      "MainExtensionNamespace"
    );

    api.logging().logToOutput("\n namespaceTest = " + namespaceTest.toString());
    api.logging().logToOutput("\npersisted namespaceTest aftr instantiation = " + api.persistence().preferences().getString("namespaceTest"));
    api.logging().logToOutput("\npersisted .namespaceTest aftr instantiation = " + api.persistence().preferences().getString(".namespaceTest"));
    api.logging().logToOutput("\npersisted MainExtensionNamespace.namespaceTest aftr instantiation = " + api.persistence().preferences().getString("MainExtensionNamespace.namespaceTest"));
  }//end initialize()
}//end class AutoPersistenceExample

interface PersistedConstituent{
  public void save();
  public void reset();
}

class GsonProvider extends DefaultGsonProvider{
  public GsonProvider(){
    super();
    this.registerTypeHierarchyAdapter(Path.class, new PathGsonifier());
    this.registerTypeAdapter(TestSwingComponent.class, new TestSwingComponent.TestSwingComponentGsonifier());
//    this.registerTypeAdapter(JCheckBox.class, new TestSwingComponent.JCheckBoxGsonifier());
//    this.registerTypeAdapter(JTextField.class, new TestSwingComponent.JTextFieldGsonifier());
  }

  static final class PathGsonifier implements JsonDeserializer<Path>, JsonSerializer<Path>{
    @Override
    public Path deserialize(
      JsonElement jsonElement, Type type, JsonDeserializationContext context
    ){
      return Path.of(jsonElement.getAsString());
    }

    @Override
    public JsonElement serialize(
      Path path, Type type, JsonSerializationContext context
    ){
      return new JsonPrimitive(path.toString());
    }
  }
}

class Settings2 extends PersistedObject{
  private boolean    activeEnabled = true;
  private Path       outFilePath   = null;
  private String     prefix        = "DefaultPrefix";
  private List<Path> inFilePaths   = new ArrayList<>();

  public Settings2(MontoyaApi api, String name, Preferences.Visibility vis){
    super(api, name, vis, new GsonProvider());
    this.register();
    _loadFromPrefs();
  }

  public boolean activeEnabled(){ return activeEnabled; }
  public boolean activeEnabled(boolean newVal){
    activeEnabled = newVal;
    save();
    return activeEnabled();
  }

  public Path outFilePath(){ return outFilePath; }
  public Path outFilePath(Path newVal){
    outFilePath = newVal;
    save();
    return outFilePath();
  }

  public String prefix(){ return prefix; }
  public String prefix(String newVal){
    prefix = newVal;
    save();
    return prefix();
  }

  public List<Path> inFilePaths(){ return inFilePaths; }
  public List<Path> inFilePaths(List<Path> newLst){
    inFilePaths = newLst;
    save();
    return inFilePaths();
  }
  public List<Path> addInFile(Path newInFilePath){
    inFilePaths.add(newInFilePath);
    save();
    return inFilePaths();
  }
  public List<Path> rmvInFile(int idx){
    inFilePaths.remove(idx);
    save();
    return inFilePaths();
  }
  public List<Path> rmvInFile(Path o){
    inFilePaths.remove(o);
    save();
    return inFilePaths();
  }

  public String toString(){
    String str =
      "activeEnabled = \n" +
        activeEnabled + "\n" +
        "\noutFilePath = \n" +
        ((outFilePath == null) ? "null" : outFilePath.toString()) + "\n" +
        "\nprefix = \n" +
        prefix + "\n" +
        "\ninFilePaths = \n" +
        inFilePaths.toString();
    return str;
  }

  //private Settings2(){ super(null, null, null); }

  private void _loadFromPrefs(){
    Settings2 persistedSelf = _prefs.get(_PERSISTED_NAME);
    this.activeEnabled = persistedSelf.activeEnabled;
    this.inFilePaths   = persistedSelf.inFilePaths;
    this.outFilePath   = persistedSelf.outFilePath;
    this.prefix        = persistedSelf.prefix;
  }
}

class ExtensionSettings extends PersistedObject{
  private SubSettings1 subSettings1 = new SubSettings1(this);
  private SubSettings2 subSettings2 = new SubSettings2(this);
  private TestSwingComponent testComponent = new TestSwingComponent(this);

  public ExtensionSettings(MontoyaApi api, String name, Preferences.Visibility vis){
    super(api, name, vis, new GsonProvider());
    this.register();
    _loadFromPrefs();
  }

  public void reset(){
    super.reset();
    _loadFromPrefs();
  }

  public SubSettings1 subSettings1(){ return subSettings1; }
  public SubSettings2 subSettings2(){ return subSettings2; }

  public String toString(){
    String str =
      "subSettings1 = \n" +
        subSettings1.toString() + "\n" +
        "\nsubSettings2 = \n" +
        subSettings2.toString() + "\n" +
        "\ntestComponent = \n" +
        testComponent.toString();
    return str;
  }

  //private ExtensionSettings(){ super(null, null, null); }

  private void _loadFromPrefs(){
    ExtensionSettings persistedSelf = _prefs.get(_PERSISTED_NAME);
    subSettings1  = new SubSettings1(this, persistedSelf.subSettings1);
    subSettings2  = new SubSettings2(this, persistedSelf.subSettings2);
    testComponent = new TestSwingComponent(this, persistedSelf.testComponent);
  }
}

class SubSettings1{
  private boolean enabled = false;

  public SubSettings1(PersistedObject manager){ _manager = manager; }
  public SubSettings1(PersistedObject manager, SubSettings1 source){
    _manager = manager;
    enabled  = source.enabled;
  }

  public void reset(){
    enabled = false;
    _manager.save();
  }

  public boolean enabled(){ return enabled; }
  public boolean enabled(boolean newVal){
    enabled = newVal;
    _manager.save();
    return enabled();
  }

  public String toString(){
    String str = "enabled = " + enabled;
    return str;
  }

  private final transient PersistedObject _manager;
}

class SubSettings2{
  private final SubSubSettings subSubSettings;
  private String str = "something";

  public SubSettings2(PersistedObject manager){
    _manager = manager;
    subSubSettings = new SubSubSettings(_manager);
  }
  public SubSettings2(PersistedObject manager, SubSettings2 source){
    _manager = manager;
    subSubSettings = new SubSubSettings(_manager, source.subSubSettings);
    str = source.str;
  }

  public void reset(){
    subSubSettings.reset();
    str = "something";
    _manager.save();
  }

  public String str(){ return str; }
  public String str(String newStr){
    str = newStr;
    _manager.save();
    return str();
  }

  public SubSubSettings subSubSettings(){ return subSubSettings; }

  public String toString(){
    String str =
      "subSubSettings = \n" +
        subSubSettings.toString() + "\n" +
        "\nstr = " + this.str;
    return str;
  }

  private final transient PersistedObject _manager;
}

class SubSubSettings{
  private boolean enabled = true;

  public SubSubSettings(PersistedObject manager){ _manager = manager; }
  public SubSubSettings(PersistedObject manager, SubSubSettings source){
    _manager = manager;
    enabled  = source.enabled;
  }

  public void reset(){ enabled = true; _manager.save(); }

  public boolean enabled(){ return enabled; }
  public boolean enabled(boolean newVal){
    enabled = newVal;
    _manager.save();
    return enabled();
  }

  public String toString(){
    String str = "enabled = " + enabled;
    return str;
  }

  private final transient PersistedObject _manager;
}

class TestSwingComponent extends JPanel implements PersistedConstituent{
  //public members accessible via functions of same name
  private final JCheckBox  gifFileType = _createOptionCheckBox(_GIF);
  private final JCheckBox  pngFileType = _createOptionCheckBox(_PNG);
  private final JTextField throttleValue = _createTextField(_STD_JTEXT_COLS);

  public TestSwingComponent(PersistedObject manager){
    _manager = manager;

    setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
    setBorder(new EmptyBorder(10, 10, 10, 10));
    this.add(gifFileType);
    this.add(pngFileType);
    this.add(_getThrottleTimeGroup());
  }
  public TestSwingComponent(PersistedObject manager, TestSwingComponent source){
    this(manager);

    gifFileType.setSelected(source.gifFileType.isSelected());
    pngFileType.setSelected(source.pngFileType.isSelected());
    throttleValue.setText(  source.throttleValue.getText());
  }

  public boolean gifFileType(){ return gifFileType.isSelected(); }
  public boolean gifFileType(boolean enable){
    gifFileType.setSelected(enable);
    return gifFileType();
  }

  public boolean pngFileType(){ return pngFileType.isSelected(); }
  public boolean pngFileType(boolean enable){
    pngFileType.setSelected(enable);
    return pngFileType();
  }

  public String throttleValue(){ return throttleValue.getText(); }
  public String throttleValue(String newVal){
    throttleValue.setText(newVal);
    return throttleValue();
  }

  public void reset(){
    gifFileType.setSelected(true);
    pngFileType.setSelected(false);
    throttleValue.setText("0");
  }

  public void save(){ _manager.save(); }

  public String toString(){
    String str =
      "_gifFileType   = " + gifFileType.isSelected() + "\n" +
        "_pngFileType   = " + pngFileType.isSelected() + "\n" +
        "_throttleValue = " + throttleValue.getText();
    return str;
  }

  private static final int       _STD_WIDTH      = 250;
  private static final int       _STD_JTEXT_COLS = 3;
  private static final int       _STD_HEIGHT     = 30;
  private static final Dimension _STD_INPUT_SIZE = new Dimension(_STD_WIDTH, _STD_HEIGHT);
  private static final String    _GIF            = "GIF images";
  private static final String    _PNG            = "PNG images";

  private final transient PersistedObject _manager;

  private static JCheckBox _createOptionCheckBox(String text) {
    JCheckBox checkBox = new JCheckBox();
    checkBox.setHorizontalTextPosition(SwingConstants.LEFT);
    checkBox.setPreferredSize(_STD_INPUT_SIZE);
    checkBox.setText(text);
    checkBox.setAlignmentX(RIGHT_ALIGNMENT);

    if(text.equals(_GIF)) checkBox.setSelected(true);
    else checkBox.setSelected(false);

    return checkBox;
  }

  private static JTextField _createTextField(int size){
    return new JTextField(size);
  }

  private JPanel _getThrottleTimeGroup() {
    final JPanel throttleTimeGroup = _getTextFileGroupPanel();

    JLabel throttleTimeLabel = new JLabel();
    throttleTimeLabel.setText("Throttle Time");
    throttleTimeGroup.add(throttleTimeLabel);

    throttleValue.setText("0");
    throttleTimeGroup.add(throttleValue);

    return throttleTimeGroup;
  }

  private static JPanel _getTextFileGroupPanel() {
    JPanel tempPanel = new JPanel();
    tempPanel.setLayout(new FlowLayout(FlowLayout.RIGHT, 5, 5));
    tempPanel.setAlignmentX(RIGHT_ALIGNMENT);
    tempPanel.setPreferredSize(_STD_INPUT_SIZE);
    return tempPanel;
  }

  static final class TestSwingComponentGsonifier
    implements JsonSerializer<TestSwingComponent>, JsonDeserializer<TestSwingComponent> {
    @Override
    public JsonElement serialize(TestSwingComponent src, Type typeOfSrc, JsonSerializationContext context) {
      JsonObject jsonObject = new JsonObject();
      for (Field field : TestSwingComponent.class.getDeclaredFields()) {
        if (!java.lang.reflect.Modifier.isTransient(field.getModifiers())) {
          field.setAccessible(true);
          try {
            if (field.get(src) instanceof JCheckBox) {
              jsonObject.addProperty(field.getName(), ((JCheckBox) field.get(src)).isSelected());
            }
            else if (field.get(src) instanceof JTextField) {
              jsonObject.addProperty(field.getName(), ((JTextField) field.get(src)).getText());
            }
            // Add other types as needed
          }
          catch (IllegalAccessException e) {
            e.printStackTrace(); // Consider proper exception handling
          }
        }
      }
      return jsonObject;
    }

    @Override
    public TestSwingComponent deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
      TestSwingComponent component = new TestSwingComponent(null);
      JsonObject jsonObject = json.getAsJsonObject();
      for (Field field : TestSwingComponent.class.getDeclaredFields()) {
        if (!java.lang.reflect.Modifier.isTransient(field.getModifiers())) {
          field.setAccessible(true);
          try {
            if (field.get(component) instanceof JCheckBox) {
              ((JCheckBox) field.get(component)).setSelected(jsonObject.get(field.getName()).getAsBoolean());
            }
            else if (field.get(component) instanceof JTextField) {
              ((JTextField) field.get(component)).setText(jsonObject.get(field.getName()).getAsString());
            }
            // Add other types as needed
          }
          catch (IllegalAccessException e) {
            e.printStackTrace(); // Consider proper exception handling
          }
        }
      }
      return component;
    }
  }
}