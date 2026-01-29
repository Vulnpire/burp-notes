package burp;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.KeyboardFocusManager;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.Transferable;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.ItemEvent;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.function.Consumer;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import javax.imageio.ImageIO;
import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.DefaultComboBoxModel;
import javax.swing.DefaultListModel;
import javax.swing.DefaultListCellRenderer;
import javax.swing.AbstractAction;
import javax.swing.Action;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JEditorPane;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JFileChooser;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JPopupMenu;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.KeyStroke;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.DefaultEditorKit;
import javax.swing.text.BadLocationException;
import javax.swing.undo.UndoManager;

public class BurpExtender implements IBurpExtender, ITab, IScopeChangeListener, IExtensionStateListener {
    private static final String EXTENSION_NAME = "Burp Notes";
    private static final String TAB_TITLE = "Notes";
    private static final String NO_TARGET = "<no in-scope targets>";
    private static final String SAMPLE_TARGET = "example.com";
    private static final String SAMPLE_VERSION = "2026-01-29";
    private static final Set<String> EXCLUDED_TAGS = new HashSet<>(Arrays.asList(
        "triage",
        "valid",
        "validated",
        "reported",
        "fixed",
        "exploiting",
        "critical",
        "high",
        "medium",
        "low",
        "severity",
        "{severity}"
    ));
    private static final String SAMPLE_NOTES = String.join("\n",
        "# Example Engagement Notes: example.com",
        "",
        "> Synthetic example to show how to structure notes. Replace tokens, IDs, and hosts with real data.",
        "",
        "## Scope",
        "- https://app.example.com",
        "- https://api.example.com",
        "- https://admin.example.com",
        "",
        "## Recon (quick)",
        "- Passive: DNS + subdomain enum, tech stack fingerprints, JS asset review.",
        "- Active: Spider, wordlists on /api, and parameter discovery on core flows.",
        "- Key endpoints discovered:",
        "  - `GET /api/v1/users/{id}/profile`",
        "  - `POST /api/v1/password/reset`",
        "  - `GET /search?q=`",
        "  - `POST /admin/templates/preview`",
        "  - `GET /auth/redirect?next=`",
        "  - `POST /api/v1/orders/search`",
        "  - `POST /api/v1/fetch`",
        "",
        "---",
        "",
        "## Finding 1: IDOR (User Profile Disclosure)",
        "**Severity:** High",
        "",
        "**Summary**",
        "A normal user can access another user's profile by changing the `userId` path parameter. The server does not validate ownership.",
        "",
        "**Impact**",
        "Disclosure of PII (name, email, phone, address) and potential pivot into other account actions.",
        "",
        "**Steps**",
        "1. Log in as a normal user (userId 10421).",
        "2. Request another user's profile by changing the path parameter.",
        "3. Observe the API returns the other user's data.",
        "",
        "**Request**",
        "```req",
        "GET /api/v1/users/10422/profile HTTP/1.1",
        "Host: api.example.com",
        "Accept: application/json",
        "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.user",
        "User-Agent: Burp",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "Cache-Control: no-store",
        "",
        "{",
        "  \"id\": 10422,",
        "  \"email\": \"victim10422@example.com\",",
        "  \"name\": \"Jamie Doe\",",
        "  \"phone\": \"+1-555-0104\",",
        "  \"address\": \"123 Market St, Apt 7\"",
        "}",
        "```",
        "",
        "**Notes**",
        "- No 403/401, response includes another user's PII.",
        "- {screenshot_20250128_101200_idor.png}",
        "",
        "**Fix**",
        "Enforce object-level access control on every request (verify the requesting user owns the resource or has the required role).",
        "",
        "---",
        "",
        "## Finding 2: Reflected XSS in Search",
        "**Severity:** Medium",
        "",
        "**Summary**",
        "The `q` parameter is reflected into HTML without encoding. JavaScript executes in the user's browser.",
        "",
        "**Impact**",
        "Session hijacking, user actions, and data exfiltration within the victim's session.",
        "",
        "**Steps**",
        "1. Navigate to the search endpoint with a script payload.",
        "2. Payload is reflected and executed.",
        "",
        "**Request**",
        "```req",
        "GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1",
        "Host: app.example.com",
        "Accept: text/html",
        "Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example.user",
        "User-Agent: Burp",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: text/html; charset=utf-8",
        "",
        "<html>",
        "  <body>",
        "    <h1>Search results for: <svg/onload=alert(1)></h1>",
        "    <div>No results.</div>",
        "  </body>",
        "</html>",
        "```",
        "",
        "**Fix**",
        "Contextually encode untrusted input and apply a strict CSP with `script-src`.",
        "",
        "---",
        "",
        "## Finding 3: Account Takeover (Password Reset + Session Persistence)",
        "**Severity:** Critical",
        "",
        "**Summary**",
        "Password reset tokens are valid for 24 hours and can be reused. Existing sessions remain valid after password reset.",
        "",
        "**Impact**",
        "Full account takeover with persistent access.",
        "",
        "**Steps**",
        "1. Trigger password reset for victim.",
        "2. Use the reset token to set a new password.",
        "3. Confirm victim's existing session remains active.",
        "4. Log in with the new password.",
        "",
        "**Request (reset token reuse)**",
        "```req",
        "POST /api/v1/password/reset HTTP/1.1",
        "Host: api.example.com",
        "Content-Type: application/json",
        "",
        "{",
        "  \"token\": \"RESET-1A2B3C4D5E6F\",",
        "  \"newPassword\": \"Attacker!2025\"",
        "}",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "",
        "{\"status\":\"ok\"}",
        "```",
        "",
        "**Request (login after reset)**",
        "```req",
        "POST /api/v1/login HTTP/1.1",
        "Host: api.example.com",
        "Content-Type: application/json",
        "",
        "{\"email\":\"victim10422@example.com\",\"password\":\"Attacker!2025\"}",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Set-Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.new.attacker; HttpOnly; Secure",
        "Content-Type: application/json",
        "",
        "{\"mfa\":\"not_required\",\"userId\":10422}",
        "```",
        "",
        "**Notes**",
        "- Reset token can be reused multiple times within 24 hours.",
        "- Existing sessions not invalidated after reset.",
        "- {screenshot_20250128_101900_ato.png}",
        "",
        "**Fix**",
        "- Make reset tokens single-use and short-lived.",
        "- Invalidate all active sessions on password change/reset.",
        "- Enforce MFA/step-up on high-risk changes.",
        "",
        "---",
        "",
        "## Finding 4: Open Redirect in OAuth Return",
        "**Severity:** Medium",
        "",
        "**Summary**",
        "The `next` parameter is not validated and allows redirects to external domains.",
        "",
        "**Impact**",
        "Phishing and token theft via malicious redirect after login.",
        "",
        "**Request**",
        "```req",
        "GET /auth/redirect?next=https://evil.example.net/callback HTTP/1.1",
        "Host: app.example.com",
        "Accept: text/html",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 302 Found",
        "Location: https://evil.example.net/callback",
        "```",
        "",
        "**Fix**",
        "Allowlist trusted domains and use relative URLs only.",
        "",
        "---",
        "",
        "## Finding 5: SSTI in Email Template Preview",
        "**Severity:** High",
        "",
        "**Summary**",
        "Admin email template preview renders server-side expressions. Input is evaluated by the template engine.",
        "",
        "**Impact**",
        "Potential server-side code execution or data exposure.",
        "",
        "**Request**",
        "```req",
        "POST /admin/templates/preview HTTP/1.1",
        "Host: admin.example.com",
        "Content-Type: application/json",
        "Cookie: session=admin.example.token",
        "",
        "{",
        "  \"template\": \"Hello {{7*7}}\",",
        "  \"context\": {\"user\":\"test\"}",
        "}",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "",
        "{\"preview\":\"Hello 49\"}",
        "```",
        "",
        "**Fix**",
        "Use a safe template engine or sandboxed mode and strictly escape user input.",
        "",
        "---",
        "",
        "## Finding 6: JWT / Token Issues (alg=none)",
        "**Severity:** High",
        "",
        "**Summary**",
        "The API accepts unsigned JWTs when `alg` is set to `none`.",
        "",
        "**Impact**",
        "An attacker can forge admin tokens and access privileged endpoints.",
        "",
        "**Request**",
        "```req",
        "GET /api/v1/admin/metrics HTTP/1.1",
        "Host: api.example.com",
        "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VySWQiOiIxMDQyMiIsInJvbGUiOiJhZG1pbiJ9.",
        "Accept: application/json",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "",
        "{\"users\":12084,\"ordersToday\":421,\"revenueToday\":17329.44}",
        "```",
        "",
        "**Fix**",
        "Reject `alg=none`, require signed tokens, and enforce server-side role checks.",
        "",
        "---",
        "",
        "## Finding 7: SQL Injection (time-based)",
        "**Severity:** High",
        "",
        "**Summary**",
        "The `q` parameter in `/api/v1/orders/search` is vulnerable to time-based SQL injection.",
        "",
        "**Request**",
        "```req",
        "POST /api/v1/orders/search HTTP/1.1",
        "Host: api.example.com",
        "Content-Type: application/json",
        "",
        "{\"q\":\"test' OR SLEEP(5)-- -\"}",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: application/json",
        "X-Response-Time: 5.02s",
        "",
        "{\"results\":[]}",
        "```",
        "",
        "**Fix**",
        "Use parameterized queries and validate/normalize input.",
        "",
        "---",
        "",
        "## Finding 8: SSRF in URL Fetcher",
        "**Severity:** Medium",
        "",
        "**Summary**",
        "The `/api/v1/fetch` endpoint fetches arbitrary URLs without an allowlist.",
        "",
        "**Request**",
        "```req",
        "POST /api/v1/fetch HTTP/1.1",
        "Host: api.example.com",
        "Content-Type: application/json",
        "",
        "{\"url\":\"http://169.254.169.254/latest/meta-data/\"}",
        "```",
        "",
        "**Response**",
        "```response",
        "HTTP/1.1 200 OK",
        "Content-Type: text/plain",
        "",
        "ami-id",
        "instance-id",
        "local-hostname",
        "```",
        "",
        "**Fix**",
        "Use strict allowlists, block internal IP ranges, and disable redirects.",
        "",
        "---",
        "",
        "## Quick Summary Table",
        "| Finding | Severity | Status |",
        "| --- | --- | --- |",
        "| IDOR (User Profile Disclosure) | High | Open |",
        "| Reflected XSS in Search | Medium | Open |",
        "| Account Takeover (Reset + Sessions) | Critical | Open |",
        "| Open Redirect in OAuth Return | Medium | Open |",
        "| SSTI in Email Template Preview | High | Open |",
        "| JWT / Token Issues (alg=none) | High | Open |",
        "| SQL Injection (time-based) | High | Open |",
        "| SSRF in URL Fetcher | Medium | Open |"
    );

    private static final String SETTINGS_TAGS = "burpnotes.tags";
    private static final String SETTINGS_STORAGE_DIR = "burpnotes.storageDir";
    private static final String SETTINGS_LAST_TARGET = "burpnotes.lastTarget";
    private static final String SETTINGS_TAG_FILTER_ENABLED = "burpnotes.tagFilterEnabled";
    private static final String SETTINGS_TAG_FILTERS = "burpnotes.tagFilters";
    private static final String SETTINGS_TAG_FILTER_MATCH_ALL = "burpnotes.tagFilterMatchAll";
    private static final String SETTINGS_EXPORT_PATH = "burpnotes.exportPath";
    private static final String SETTINGS_COLLAPSE_TAGS = "burpnotes.collapse.tags";
    private static final String SETTINGS_COLLAPSE_CHECKLISTS = "burpnotes.collapse.checklists";
    private static final String SETTINGS_DIVIDER_MAIN = "burpnotes.divider.main";
    private static final String SETTINGS_UNLOAD_INACTIVE = "burpnotes.unloadInactiveTargets";
    private static final String SETTINGS_SHOW_OUTLINE = "burpnotes.showOutline";

    private static final String NOTES_FILE_NAME = "notes.properties";
    private static final String ATTACHMENTS_DIR_NAME = "attachments";
    private static final int PREVIEW_IMAGE_MAX_WIDTH = 1200;
    private static final int PREVIEW_IMAGE_MAX_HEIGHT = 900;
    private static final int PREVIEW_INLINE_MAX_WIDTH = 260;
    private static final int PREVIEW_INLINE_MAX_HEIGHT = 180;

    private static final Set<String> FALLBACK_MULTI_PART_TLDS = new HashSet<>(Arrays.asList(
        "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
        "co.nz", "org.nz", "govt.nz", "ac.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
        "co.kr", "or.kr", "go.kr",
        "com.br", "com.ar", "com.mx", "com.tr",
        "com.cn", "com.hk", "com.sg",
        "co.in", "firm.in", "net.in", "org.in", "gen.in",
        "co.za", "org.za", "gov.za"
    ));

    private static final LanguageProfile GENERIC_PROFILE = new LanguageProfile(
        keywordSet(),
        Arrays.asList("//", "#", "--"),
        "/*",
        "*/",
        true,
        false
    );

    private static final Map<String, LanguageProfile> LANGUAGE_PROFILES = buildLanguageProfiles();

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel rootPanel;
    private JTabbedPane tabbedPane;

    private JPanel notesHostPanel;
    private CardLayout notesHostLayout;
    private JPanel notesContentPanel;
    private JPanel notesDetachedPanel;
    private JButton detachNotesButton;
    private JButton attachNotesButton;
    private JFrame detachedFrame;
    private boolean isReattaching;
    private NotesViewState embeddedViewState;
    private NotesViewState detachedViewState;
    private JPanel detachedNotesPanel;
    private JSplitPane notesMainSplitPane;
    private JSplitPane notesEditorSplit;
    private JPanel outlinePanel;
    private JPanel outlinePlaceholder;

    private JTextArea notesArea;
    private UndoManager notesUndoManager;
    private JEditorPane markdownPreview;
    private JTabbedPane notesEditorTabs;
    private DefaultListModel<OutlineEntry> outlineListModel;
    private JList<OutlineEntry> outlineList;
    private Timer outlineUpdateTimer;
    private boolean outlineUpdating;
    private boolean showOutline = true;
    private JLabel notesTargetLabel;
    private boolean previewDirty;

    private DefaultComboBoxModel<String> targetModel;
    private JComboBox<String> targetCombo;
    private JButton refreshTargetsButton;

    private JCheckBox autoSaveCheck;
    private JTextField storageDirectoryField;

    private DefaultListModel<String> tagListModel;
    private JList<String> tagList;
    private JTextField newTagField;
    private JButton addTagButton;
    private JPanel tagChecklistContainer;
    private JScrollPane tagChecklistScroll;
    private JTextField addChecklistItemField;
    private JButton addChecklistButton;
    private final Map<String, TagChecklistCard> checklistCards = new HashMap<>();
    private JDialog searchDialog;
    private JTextField searchDialogField;
    private DefaultListModel<SearchResult> searchResultsModel;
    private JList<SearchResult> searchResultsList;
    private Timer searchDialogTimer;

    private DefaultListModel<String> attachmentListModel;
    private JList<String> attachmentList;
    private JButton pasteScreenshotButton;
    private JButton removeAttachmentButton;
    private JButton renameAttachmentButton;

    private Color appBackground;
    private Color surfaceBackground;
    private Color borderColor;
    private Color accentColor;
    private Color mutedText;
    private boolean isDarkTheme;
    private Color syntaxKeywordColor;
    private Color syntaxStringColor;
    private Color syntaxCommentColor;
    private Color syntaxNumberColor;
    private Color syntaxHeaderColor;

    private Font headerFont;
    private Font sectionFont;
    private Font bodyFont;
    private Font monoFont;

    private final Map<String, TargetState> targetStates = new HashMap<>();
    private final Set<String> globalTags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    private final Set<String> activeTagFilters = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    private String currentTarget;
    private String preferredTarget;
    private String storageDirectory;
    private boolean isLoadingState;
    private boolean isRefreshingTargets;
    private boolean tagFilterEnabled;
    private boolean tagFilterMatchAll = true;
    private String exportPath;
    private DefaultListModel<String> tagFilterListModel;
    private JList<String> tagFilterList;
    private JCheckBox tagFilterEnabledCheck;
    private JCheckBox tagFilterMatchAllCheck;
    private JTextArea tagAnalyticsArea;
    private JButton refreshAnalyticsButton;
    private JTextField exportPathField;
    private JButton exportButton;
    private JCheckBox exportUseFilterCheck;
    private DefaultListModel<String> exportTargetsListModel;
    private JList<String> exportTargetsList;
    private JButton refreshExportTargetsButton;
    private JComboBox<String> exportFormatCombo;
    private JTextField exportSelectedPathField;
    private JButton exportSelectedButton;
    private JTextField importPathField;
    private JComboBox<String> importModeCombo;
    private JCheckBox importReplaceCheck;
    private JButton importButton;
    private JLabel memoryUsageLabel;
    private Timer memoryUsageTimer;
    private JCheckBox unloadInactiveTargetsCheck;
    private JCheckBox showOutlineCheck;
    private boolean unloadInactiveTargets;
    private JButton deleteTargetDataButton;
    private JButton clearAllDataButton;

    private Timer autoSaveTimer;
    private java.util.concurrent.ExecutorService saveExecutor;
    private PublicSuffixList publicSuffixList;
    private boolean searchDispatcherInstalled;

    private boolean tagsCollapsed;
    private boolean checklistsCollapsed;
    private Integer mainDividerLocation;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerScopeChangeListener(this);
        callbacks.registerExtensionStateListener(this);

        SwingUtilities.invokeLater(() -> {
            initTheme();
            loadGlobalSettings();
            initPublicSuffixList();
            buildUi();
            callbacks.addSuiteTab(this);
            refreshTargets();
        });
    }

    @Override
    public String getTabCaption() {
        return TAB_TITLE;
    }

    @Override
    public Component getUiComponent() {
        return rootPanel;
    }

    @Override
    public void scopeChanged() {
        SwingUtilities.invokeLater(this::refreshTargets);
    }

    @Override
    public void extensionUnloaded() {
        SwingUtilities.invokeLater(() -> {
            cancelAutoSave();
            stopMemoryUsageTimer();
            flushAllState();
            shutdownSaveExecutor();
        });
    }

    private void initTheme() {
        Color panel = getUiColor("Panel.background", new Color(245, 247, 250));
        Color field = getUiColor("TextField.background", panel);
        Color focus = getUiColor("Component.focusColor", getUiColor("textHighlight", getUiColor("Label.foreground", new Color(80, 90, 100))));
        Color muted = getUiColor("Label.disabledForeground", getUiColor("Label.foreground", new Color(90, 96, 104)));
        Color border = getUiColor("Separator.foreground", getUiColor("controlShadow", new Color(180, 185, 190)));

        appBackground = panel;
        surfaceBackground = field;
        accentColor = focus;
        mutedText = muted;
        borderColor = border;

        isDarkTheme = isDarkColor(appBackground);
        if (isDarkTheme) {
            syntaxKeywordColor = new Color(129, 201, 255);
            syntaxStringColor = new Color(171, 219, 171);
            syntaxCommentColor = new Color(140, 150, 160);
            syntaxNumberColor = new Color(255, 205, 140);
            syntaxHeaderColor = new Color(255, 170, 110);
        } else {
            syntaxKeywordColor = new Color(0, 92, 170);
            syntaxStringColor = new Color(0, 128, 0);
            syntaxCommentColor = new Color(120, 120, 120);
            syntaxNumberColor = new Color(160, 90, 0);
            syntaxHeaderColor = new Color(170, 70, 0);
        }

        Font base = getUiFont("Label.font", new Font("SansSerif", Font.PLAIN, 12));
        bodyFont = base;
        headerFont = base.deriveFont(Font.BOLD, base.getSize() + 4.0f);
        sectionFont = base.deriveFont(Font.BOLD, base.getSize() + 1.0f);
        monoFont = getUiFont("TextArea.font", new Font("Monospaced", Font.PLAIN, base.getSize()));
    }

    private void loadGlobalSettings() {
        storageDirectory = safeTrim(callbacks.loadExtensionSetting(SETTINGS_STORAGE_DIR));
        if (storageDirectory.isEmpty()) {
            storageDirectory = getDefaultStorageDirectory();
        }

        String tagSetting = callbacks.loadExtensionSetting(SETTINGS_TAGS);
        if (tagSetting != null && !tagSetting.trim().isEmpty()) {
            for (String line : tagSetting.split("\\R")) {
                String cleaned = normalizeTag(line);
                if (!cleaned.isEmpty()) {
                    globalTags.add(cleaned);
                }
            }
        }
        globalTags.addAll(TagLibrary.getAllTagNames());
        removeExcludedTags();

        String last = safeTrim(callbacks.loadExtensionSetting(SETTINGS_LAST_TARGET));
        if (!last.isEmpty()) {
            preferredTarget = last;
        }

        String filterEnabled = safeTrim(callbacks.loadExtensionSetting(SETTINGS_TAG_FILTER_ENABLED));
        if (!filterEnabled.isEmpty()) {
            tagFilterEnabled = Boolean.parseBoolean(filterEnabled);
        }

        String filterMatchAll = safeTrim(callbacks.loadExtensionSetting(SETTINGS_TAG_FILTER_MATCH_ALL));
        if (!filterMatchAll.isEmpty()) {
            tagFilterMatchAll = Boolean.parseBoolean(filterMatchAll);
        }

        String filterTags = callbacks.loadExtensionSetting(SETTINGS_TAG_FILTERS);
        if (filterTags != null && !filterTags.trim().isEmpty()) {
            for (String tag : filterTags.split("\\R")) {
                String cleaned = normalizeTag(tag);
                if (!cleaned.isEmpty()) {
                    activeTagFilters.add(cleaned);
                }
            }
        }
        removeExcludedTags();

        exportPath = safeTrim(callbacks.loadExtensionSetting(SETTINGS_EXPORT_PATH));
        if (exportPath.isEmpty()) {
            exportPath = getDefaultExportPath();
        }

        String tagsCollapsedSetting = safeTrim(callbacks.loadExtensionSetting(SETTINGS_COLLAPSE_TAGS));
        if (!tagsCollapsedSetting.isEmpty()) {
            tagsCollapsed = Boolean.parseBoolean(tagsCollapsedSetting);
        }

        String checklistsCollapsedSetting = safeTrim(callbacks.loadExtensionSetting(SETTINGS_COLLAPSE_CHECKLISTS));
        if (!checklistsCollapsedSetting.isEmpty()) {
            checklistsCollapsed = Boolean.parseBoolean(checklistsCollapsedSetting);
        }

        mainDividerLocation = parseDividerLocation(callbacks.loadExtensionSetting(SETTINGS_DIVIDER_MAIN));

        String unloadSetting = safeTrim(callbacks.loadExtensionSetting(SETTINGS_UNLOAD_INACTIVE));
        if (!unloadSetting.isEmpty()) {
            unloadInactiveTargets = Boolean.parseBoolean(unloadSetting);
        }

        String outlineSetting = safeTrim(callbacks.loadExtensionSetting(SETTINGS_SHOW_OUTLINE));
        if (!outlineSetting.isEmpty()) {
            showOutline = Boolean.parseBoolean(outlineSetting);
        }

        ensureSampleNotes();
    }

    private void saveGlobalTags() {
        if (callbacks == null) {
            return;
        }
        StringBuilder sb = new StringBuilder();
        for (String tag : globalTags) {
            sb.append(tag).append("\n");
        }
        callbacks.saveExtensionSetting(SETTINGS_TAGS, sb.toString().trim());
    }

    private void saveStorageDirectory() {
        if (callbacks == null) {
            return;
        }
        callbacks.saveExtensionSetting(SETTINGS_STORAGE_DIR, storageDirectory);
    }

    private void saveLastTarget() {
        if (callbacks == null) {
            return;
        }
        if (currentTarget != null) {
            callbacks.saveExtensionSetting(SETTINGS_LAST_TARGET, currentTarget);
        }
    }

    private void saveTagFilterSettings() {
        if (callbacks == null) {
            return;
        }
        callbacks.saveExtensionSetting(SETTINGS_TAG_FILTER_ENABLED, Boolean.toString(tagFilterEnabled));
        callbacks.saveExtensionSetting(SETTINGS_TAG_FILTER_MATCH_ALL, Boolean.toString(tagFilterMatchAll));
        StringBuilder sb = new StringBuilder();
        for (String tag : activeTagFilters) {
            sb.append(tag).append("\n");
        }
        callbacks.saveExtensionSetting(SETTINGS_TAG_FILTERS, sb.toString().trim());
    }

    private void saveExportPath() {
        if (callbacks == null) {
            return;
        }
        callbacks.saveExtensionSetting(SETTINGS_EXPORT_PATH, exportPath == null ? "" : exportPath);
    }

    private void saveLayoutSettings() {
        if (callbacks == null) {
            return;
        }
        callbacks.saveExtensionSetting(SETTINGS_COLLAPSE_TAGS, Boolean.toString(tagsCollapsed));
        callbacks.saveExtensionSetting(SETTINGS_COLLAPSE_CHECKLISTS, Boolean.toString(checklistsCollapsed));
        callbacks.saveExtensionSetting(SETTINGS_SHOW_OUTLINE, Boolean.toString(showOutline));
        if (mainDividerLocation != null) {
            callbacks.saveExtensionSetting(SETTINGS_DIVIDER_MAIN, Integer.toString(mainDividerLocation));
        }
    }

    private void savePerformanceSettings() {
        if (callbacks == null) {
            return;
        }
        callbacks.saveExtensionSetting(SETTINGS_UNLOAD_INACTIVE, Boolean.toString(unloadInactiveTargets));
    }

    private void removeExcludedTags() {
        if (!globalTags.isEmpty()) {
            globalTags.removeIf(tag -> isExcludedTag(tag));
        }
        if (!activeTagFilters.isEmpty()) {
            activeTagFilters.removeIf(tag -> isExcludedTag(tag));
        }
    }

    private boolean isExcludedTag(String tag) {
        if (tag == null) {
            return false;
        }
        String cleaned = tag.trim().toLowerCase(Locale.ROOT);
        return EXCLUDED_TAGS.contains(cleaned);
    }

    private String truncateTitle(String text, int max) {
        if (text == null) {
            return "";
        }
        String trimmed = text.trim();
        if (trimmed.length() <= max) {
            return trimmed;
        }
        int limit = Math.max(3, max - 3);
        return trimmed.substring(0, limit) + "...";
    }

    private void ensureSampleNotes() {
        Path targetDir = getTargetStorageDir(SAMPLE_TARGET);
        if (targetDir == null) {
            return;
        }
        Path notesFile = targetDir.resolve(NOTES_FILE_NAME);
        if (Files.exists(notesFile)) {
            Properties existing = new Properties();
            try (InputStream in = Files.newInputStream(notesFile)) {
                existing.load(in);
            } catch (IOException e) {
                // fall through and attempt to overwrite
            }
            String version = safeTrim(existing.getProperty("sampleVersion"));
            if (SAMPLE_VERSION.equals(version)) {
                return;
            }
        }
        try {
            Files.createDirectories(targetDir);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to create sample notes directory: " + e.getMessage());
            }
            return;
        }

        Properties props = new Properties();
        props.setProperty("sampleVersion", SAMPLE_VERSION);
        props.setProperty("notes", encodeBase64(SAMPLE_NOTES));
        props.setProperty("autoSave", "false");
        props.setProperty("tags", "");
        props.setProperty("attachments", "");
        props.setProperty("checklists", "");
        props.setProperty("customChecklistItems", "");
        props.setProperty("customChecklists", "");

        try (OutputStream out = Files.newOutputStream(notesFile)) {
            props.store(out, "Burp Notes sample");
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to write sample notes: " + e.getMessage());
            }
        }
    }

    private void startMemoryUsageTimer() {
        if (memoryUsageTimer != null) {
            return;
        }
        memoryUsageTimer = new Timer(2000, event -> updateMemoryUsageLabel());
        memoryUsageTimer.start();
        updateMemoryUsageLabel();
    }

    private void stopMemoryUsageTimer() {
        if (memoryUsageTimer != null) {
            memoryUsageTimer.stop();
            memoryUsageTimer = null;
        }
    }

    private void updateMemoryUsageLabel() {
        if (memoryUsageLabel == null) {
            return;
        }
        long estimate = estimateExtensionMemoryBytes();
        memoryUsageLabel.setText("Extension memory (approx): " + formatBytes(estimate));

        Runtime runtime = Runtime.getRuntime();
        long used = runtime.totalMemory() - runtime.freeMemory();
        long max = runtime.maxMemory();
        memoryUsageLabel.setToolTipText("JVM total (Burp + extensions): "
            + formatBytes(used) + " used / " + formatBytes(max) + " max");
    }

    private long estimateExtensionMemoryBytes() {
        long total = 0;
        total += approxStringBytes(storageDirectory);
        total += approxStringBytes(exportPath);
        total += approxStringBytes(currentTarget);
        total += approxStringBytes(preferredTarget);
        total += approxStringBytes(NO_TARGET);

        for (String tag : globalTags) {
            total += approxStringBytes(tag);
        }
        for (String tag : activeTagFilters) {
            total += approxStringBytes(tag);
        }

        for (TargetState state : targetStates.values()) {
            if (state == null) {
                continue;
            }
            total += approxStringBytes(state.notesText);
            for (String tag : state.selectedTags) {
                total += approxStringBytes(tag);
            }
            for (String name : state.attachments) {
                total += approxStringBytes(name);
            }
            for (Map.Entry<String, String> entry : state.attachmentHashes.entrySet()) {
                total += approxStringBytes(entry.getKey());
                total += approxStringBytes(entry.getValue());
            }
            for (Map.Entry<String, TagChecklistState> entry : state.checklistStates.entrySet()) {
                total += approxStringBytes(entry.getKey());
                TagChecklistState checklistState = entry.getValue();
                if (checklistState == null) {
                    continue;
                }
                for (Map.Entry<String, ChecklistItemState> itemEntry : checklistState.itemStates.entrySet()) {
                    total += approxStringBytes(itemEntry.getKey());
                }
            }
            for (Map.Entry<String, List<String>> entry : state.customChecklistItems.entrySet()) {
                total += approxStringBytes(entry.getKey());
                List<String> items = entry.getValue();
                if (items == null) {
                    continue;
                }
                for (String item : items) {
                    total += approxStringBytes(item);
                }
            }
            for (CustomChecklist checklist : state.customChecklists.values()) {
                if (checklist == null) {
                    continue;
                }
                total += approxStringBytes(checklist.id);
                total += approxStringBytes(checklist.title);
                total += approxStringBytes(checklist.afterKey);
                if (checklist.items != null) {
                    for (String item : checklist.items) {
                        total += approxStringBytes(item);
                    }
                }
            }
        }

        return total;
    }

    private long approxStringBytes(String value) {
        if (value == null) {
            return 0;
        }
        return 40L + (long) value.length() * 2L;
    }

    private String formatBytes(long bytes) {
        if (bytes <= 0) {
            return "0 KB";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024.0) {
            return String.format(Locale.ROOT, "%.0f KB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024.0) {
            return String.format(Locale.ROOT, "%.1f MB", mb);
        }
        double gb = mb / 1024.0;
        return String.format(Locale.ROOT, "%.1f GB", gb);
    }

    private void unloadInactiveTargetStates() {
        if (!unloadInactiveTargets || targetStates.isEmpty()) {
            return;
        }
        Iterator<Map.Entry<String, TargetState>> iterator = targetStates.entrySet().iterator();
        while (iterator.hasNext()) {
            Map.Entry<String, TargetState> entry = iterator.next();
            String target = entry.getKey();
            if (currentTarget != null && currentTarget.equals(target)) {
                continue;
            }
            TargetState state = entry.getValue();
            if (state != null && state.dirty) {
                enqueueSave(target, state);
            }
            iterator.remove();
        }
    }

    private void deleteTargetData(String target) {
        if (target == null || target.trim().isEmpty()) {
            return;
        }
        boolean wasCurrent = Objects.equals(currentTarget, target);
        if (wasCurrent) {
            cancelAutoSave();
            currentTarget = null;
        }
        targetStates.remove(target);
        Path targetDir = getTargetStorageDir(target);
        deleteDirectory(targetDir);
        if (wasCurrent) {
            if (callbacks != null) {
                callbacks.saveExtensionSetting(SETTINGS_LAST_TARGET, "");
            }
            loadCurrentTargetState();
        }
        refreshTargets();
    }

    private void clearAllExtensionData() {
        cancelAutoSave();
        targetStates.clear();
        currentTarget = null;
        preferredTarget = null;

        Path baseDir = resolvePath(storageDirectory == null || storageDirectory.trim().isEmpty()
            ? getDefaultStorageDirectory()
            : storageDirectory);
        deleteDirectory(baseDir);

        globalTags.clear();
        globalTags.addAll(TagLibrary.getAllTagNames());
        activeTagFilters.clear();
        tagFilterEnabled = false;
        tagFilterMatchAll = true;

        if (tagFilterEnabledCheck != null) {
            tagFilterEnabledCheck.setSelected(tagFilterEnabled);
        }
        if (tagFilterMatchAllCheck != null) {
            tagFilterMatchAllCheck.setSelected(tagFilterMatchAll);
        }
        if (tagFilterList != null) {
            tagFilterList.clearSelection();
        }

        saveGlobalTags();
        saveTagFilterSettings();
        if (callbacks != null) {
            callbacks.saveExtensionSetting(SETTINGS_LAST_TARGET, "");
        }

        loadCurrentTargetState();
        refreshTargets();
    }

    private void deleteDirectory(Path path) {
        if (path == null || !Files.exists(path)) {
            return;
        }
        try (java.util.stream.Stream<Path> walk = Files.walk(path)) {
            walk.sorted(Comparator.reverseOrder()).forEach(entry -> {
                try {
                    Files.deleteIfExists(entry);
                } catch (IOException e) {
                    if (callbacks != null) {
                        callbacks.printError("Failed to delete: " + entry + " (" + e.getMessage() + ")");
                    }
                }
            });
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to delete directory: " + e.getMessage());
            }
        }
    }

    private void initPublicSuffixList() {
        publicSuffixList = PublicSuffixList.load();
    }

    private void buildUi() {
        rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(appBackground);
        tabbedPane = new JTabbedPane();
        tabbedPane.setFont(bodyFont);

        tabbedPane.addTab("Notes", buildNotesPanel());
        tabbedPane.addTab("Cheatsheet", buildCheatsheetPanel());
        tabbedPane.addTab("Options", buildOptionsPanel());

        rootPanel.add(tabbedPane, BorderLayout.CENTER);
        registerSearchHotkey(rootPanel);
        installGlobalSearchDispatcher();
        customizeRecursive(rootPanel);
    }

    private void customizeRecursive(Component component) {
        if (callbacks != null) {
            callbacks.customizeUiComponent(component);
        }
        if (component instanceof Container) {
            for (Component child : ((Container) component).getComponents()) {
                customizeRecursive(child);
            }
        }
    }

    private JPanel buildNotesPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(appBackground);

        notesHostLayout = new CardLayout();
        notesHostPanel = new JPanel(notesHostLayout);
        notesHostPanel.setBackground(appBackground);

        notesContentPanel = buildNotesContentPanel();
        embeddedViewState = captureNotesViewState();
        notesDetachedPanel = buildNotesDetachedPanel();

        notesHostPanel.add(notesContentPanel, "content");
        notesHostPanel.add(notesDetachedPanel, "detached");
        notesHostLayout.show(notesHostPanel, "content");

        panel.add(notesHostPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildNotesContentPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(appBackground);

        panel.add(buildNotesHeader(), BorderLayout.NORTH);

        notesMainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildLeftNotesPanel(), buildNotesEditorPanel());
        notesMainSplitPane.setResizeWeight(0.34);
        notesMainSplitPane.setBorder(BorderFactory.createEmptyBorder(8, 12, 12, 12));
        notesMainSplitPane.setDividerSize(6);
        notesMainSplitPane.setContinuousLayout(true);
        if (mainDividerLocation != null) {
            notesMainSplitPane.setDividerLocation(mainDividerLocation);
        }
        notesMainSplitPane.addPropertyChangeListener(JSplitPane.DIVIDER_LOCATION_PROPERTY, event -> {
            mainDividerLocation = notesMainSplitPane.getDividerLocation();
            saveLayoutSettings();
        });

        panel.add(notesMainSplitPane, BorderLayout.CENTER);
        registerSearchHotkey(panel);
        return panel;
    }

    private JPanel buildLeftNotesPanel() {
        JPanel left = new JPanel();
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));
        left.setBackground(appBackground);

        JPanel tagsPanel = buildTagsPanel();
        JPanel checklistPanel = buildChecklistPanel();

        tagsPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        checklistPanel.setAlignmentX(Component.LEFT_ALIGNMENT);

        left.add(tagsPanel);
        left.add(Box.createVerticalStrut(10));
        left.add(checklistPanel);

        return left;
    }

    private JPanel buildNotesDetachedPanel() {
        JPanel panel = new JPanel();
        panel.setBackground(appBackground);
        panel.setLayout(new BoxLayout(panel, BoxLayout.Y_AXIS));
        panel.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));

        JLabel label = new JLabel("Notes are detached in a separate window.");
        label.setFont(sectionFont);
        label.setForeground(mutedText);
        label.setAlignmentX(Component.LEFT_ALIGNMENT);

        attachNotesButton = new JButton("Attach back to Burp");
        attachNotesButton.setFont(bodyFont);
        attachNotesButton.setAlignmentX(Component.LEFT_ALIGNMENT);
        attachNotesButton.addActionListener(event -> attachNotes());

        panel.add(label);
        panel.add(Box.createVerticalStrut(8));
        panel.add(attachNotesButton);

        return panel;
    }

    private JPanel buildNotesHeader() {
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(appBackground);
        header.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));

        JLabel title = new JLabel("Engagement Notes");
        title.setFont(headerFont);
        title.setForeground(accentColor);

        notesTargetLabel = new JLabel("Current target: (none)");
        notesTargetLabel.setFont(bodyFont);
        notesTargetLabel.setForeground(mutedText);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setBackground(appBackground);
        textPanel.add(title);
        textPanel.add(Box.createVerticalStrut(4));
        textPanel.add(notesTargetLabel);

        detachNotesButton = new JButton("Detach");
        detachNotesButton.setFont(bodyFont);
        detachNotesButton.addActionListener(event -> toggleDetach());

        header.add(textPanel, BorderLayout.WEST);
        header.add(detachNotesButton, BorderLayout.EAST);
        return header;
    }

    private JPanel buildTagsPanel() {
        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.setBackground(surfaceBackground);

        JLabel hint = new JLabel("Select tags for this target.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        if (tagListModel == null) {
            tagListModel = new DefaultListModel<>();
        }
        tagList = new JList<>(tagListModel);
        tagList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        tagList.setVisibleRowCount(10);
        tagList.setFont(bodyFont);
        tagList.setBackground(surfaceBackground);
        tagList.setEnabled(false);
        tagList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting()) {
                updateCurrentTagsFromUi();
            }
        });

        initDefaultTags();

        JScrollPane listScroll = new JScrollPane(tagList);
        listScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        JPanel addPanel = new JPanel(new BorderLayout(8, 0));
        addPanel.setBackground(surfaceBackground);
        newTagField = new JTextField();
        newTagField.setFont(bodyFont);
        newTagField.addActionListener(event -> addNewTag());
        newTagField.setEnabled(false);

        addTagButton = new JButton("Add");
        addTagButton.setFont(bodyFont);
        addTagButton.addActionListener(event -> addNewTag());
        addTagButton.setEnabled(false);

        addPanel.add(newTagField, BorderLayout.CENTER);
        addPanel.add(addTagButton, BorderLayout.EAST);

        content.add(hint, BorderLayout.NORTH);
        content.add(listScroll, BorderLayout.CENTER);
        content.add(addPanel, BorderLayout.SOUTH);

        return createCollapsibleSectionPanel("Tags", content, "tags", false);
    }

    private JPanel buildChecklistPanel() {
        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.setBackground(surfaceBackground);

        JLabel hint = new JLabel("Checklist cards from selected tags.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        tagChecklistContainer = new JPanel();
        tagChecklistContainer.setLayout(new BoxLayout(tagChecklistContainer, BoxLayout.Y_AXIS));
        tagChecklistContainer.setBackground(surfaceBackground);

        tagChecklistScroll = new JScrollPane(tagChecklistContainer);
        tagChecklistScroll.setBorder(BorderFactory.createLineBorder(borderColor));
        tagChecklistScroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        tagChecklistScroll.getVerticalScrollBar().setUnitIncrement(12);
        tagChecklistScroll.setPreferredSize(new Dimension(0, 240));

        addChecklistItemField = new JTextField();
        addChecklistItemField.setFont(bodyFont);
        addChecklistItemField.setEnabled(false);
        addChecklistItemField.addActionListener(event -> addChecklistItem());

        addChecklistButton = new JButton("Add");
        addChecklistButton.setFont(bodyFont);
        addChecklistButton.setEnabled(false);
        addChecklistButton.addActionListener(event -> addChecklistItem());

        JPanel actions = new JPanel(new BorderLayout(8, 0));
        actions.setBackground(surfaceBackground);
        actions.add(addChecklistItemField, BorderLayout.CENTER);
        actions.add(addChecklistButton, BorderLayout.EAST);

        content.add(hint, BorderLayout.NORTH);
        content.add(tagChecklistScroll, BorderLayout.CENTER);
        content.add(actions, BorderLayout.SOUTH);

        return createCollapsibleSectionPanel("Checklists", content, "checklists", false);
    }

    private JPanel buildNotesEditorPanel() {
        JPanel content = new JPanel(new BorderLayout(0, 10));
        content.setBackground(surfaceBackground);

        JLabel hint = new JLabel("Write notes in Markdown (.md) and preview them in the tab.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        notesArea = new JTextArea();
        notesArea.setLineWrap(true);
        notesArea.setWrapStyleWord(true);
        notesArea.setFont(monoFont);
        notesArea.setBackground(surfaceBackground);
        notesArea.setCaretColor(accentColor);
        notesArea.setMargin(new Insets(8, 8, 8, 8));
        notesArea.setEnabled(false);
        installUndoRedo(notesArea);
        notesArea.getDocument().addDocumentListener(new SimpleDocumentListener(() -> {
            updateCurrentStateFromUi();
            previewDirty = true;
            if (notesEditorTabs != null && notesEditorTabs.getSelectedIndex() == 1) {
                syncMarkdownPreview();
            }
            queueOutlineUpdate();
        }));
        installPasteHandler(notesArea, true);

        JScrollPane editorScroll = new JScrollPane(notesArea);
        editorScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        markdownPreview = new JEditorPane();
        markdownPreview.setEditable(false);
        markdownPreview.setContentType("text/html");
        markdownPreview.setFont(bodyFont);
        markdownPreview.setBackground(surfaceBackground);
        markdownPreview.setMargin(new Insets(8, 8, 8, 8));
        markdownPreview.setText(renderMarkdownToHtml(""));
        installPasteHandler(markdownPreview, false);

        JScrollPane previewScroll = new JScrollPane(markdownPreview);
        previewScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        notesEditorTabs = new JTabbedPane();
        notesEditorTabs.setFont(bodyFont);
        notesEditorTabs.addTab("Editor (.md)", editorScroll);
        notesEditorTabs.addTab("Preview", previewScroll);
        notesEditorTabs.setEnabled(false);
        notesEditorTabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent event) {
                if (notesEditorTabs.getSelectedIndex() == 1 && previewDirty) {
                    syncMarkdownPreview();
                }
            }
        });

        outlinePanel = buildOutlinePanel();
        outlinePlaceholder = new JPanel();
        outlinePlaceholder.setBackground(appBackground);
        notesEditorSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, notesEditorTabs, outlinePanel);
        notesEditorSplit.setResizeWeight(0.8);
        notesEditorSplit.setDividerSize(6);
        notesEditorSplit.setContinuousLayout(true);
        notesEditorSplit.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        updateOutlineVisibility();

        JPanel attachmentsPanel = buildAttachmentsPanel();

        content.add(hint, BorderLayout.NORTH);
        content.add(notesEditorSplit, BorderLayout.CENTER);
        content.add(attachmentsPanel, BorderLayout.SOUTH);

        return createSectionPanel("Notes", content);
    }

    private JPanel buildOutlinePanel() {
        JPanel content = new JPanel(new BorderLayout(0, 6));
        content.setBackground(surfaceBackground);

        JLabel hint = new JLabel("Headings (#) in this note.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        outlineListModel = new DefaultListModel<>();
        outlineList = new JList<>(outlineListModel);
        outlineList.setFont(bodyFont);
        outlineList.setBackground(blend(surfaceBackground, appBackground, 0.08f));
        outlineList.setSelectionBackground(blend(accentColor, surfaceBackground, isDarkTheme ? 0.35f : 0.2f));
        outlineList.setSelectionForeground(getUiColor("Label.foreground", Color.WHITE));
        outlineList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        outlineList.setEnabled(false);
        outlineList.setFixedCellHeight(26);
        outlineList.setCellRenderer(new OutlineCellRenderer());
        outlineList.addListSelectionListener(event -> {
            if (event.getValueIsAdjusting() || outlineUpdating) {
                return;
            }
            OutlineEntry entry = outlineList.getSelectedValue();
            if (entry == null || entry.lineNumber <= 0) {
                return;
            }
            jumpToOutlineEntry(entry);
        });

        JScrollPane scrollPane = new JScrollPane(outlineList);
        scrollPane.setBorder(BorderFactory.createLineBorder(borderColor));
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(12);
        scrollPane.setPreferredSize(new Dimension(220, 0));

        content.add(hint, BorderLayout.NORTH);
        content.add(scrollPane, BorderLayout.CENTER);

        JPanel panel = createSectionPanel("Outline", content);
        panel.setPreferredSize(new Dimension(240, 0));
        return panel;
    }

    private void updateOutlineVisibility() {
        if (notesEditorSplit == null) {
            return;
        }
        if (showOutline) {
            if (outlinePanel != null && notesEditorSplit.getRightComponent() != outlinePanel) {
                notesEditorSplit.setRightComponent(outlinePanel);
            }
            notesEditorSplit.setDividerSize(6);
            notesEditorSplit.setEnabled(true);
            notesEditorSplit.setDividerLocation(0.78);
            if (outlineList != null) {
                outlineList.setEnabled(currentTarget != null);
            }
        } else {
            if (outlinePlaceholder == null) {
                outlinePlaceholder = new JPanel();
                outlinePlaceholder.setBackground(appBackground);
            }
            notesEditorSplit.setRightComponent(outlinePlaceholder);
            notesEditorSplit.setDividerLocation(1.0d);
            notesEditorSplit.setDividerSize(0);
            notesEditorSplit.setEnabled(false);
            if (outlineList != null) {
                outlineList.setEnabled(false);
            }
        }
        notesEditorSplit.revalidate();
        notesEditorSplit.repaint();
    }

    private JPanel buildAttachmentsPanel() {
        JPanel panel = new JPanel(new BorderLayout(0, 6));
        panel.setBackground(surfaceBackground);

        JLabel title = new JLabel("Attachments");
        title.setFont(sectionFont);
        title.setForeground(accentColor);

        attachmentListModel = new DefaultListModel<>();
        attachmentList = new JList<>(attachmentListModel);
        attachmentList.setVisibleRowCount(4);
        attachmentList.setFont(bodyFont);
        attachmentList.setBackground(surfaceBackground);
        attachmentList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        attachmentList.setEnabled(false);
        installPasteHandler(attachmentList, false);

        JScrollPane listScroll = new JScrollPane(attachmentList);
        listScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        pasteScreenshotButton = new JButton("Paste Screenshot");
        pasteScreenshotButton.setFont(bodyFont);
        pasteScreenshotButton.setEnabled(false);
        pasteScreenshotButton.addActionListener(event -> pasteScreenshot());

        removeAttachmentButton = new JButton("Remove");
        removeAttachmentButton.setFont(bodyFont);
        removeAttachmentButton.setEnabled(false);
        removeAttachmentButton.addActionListener(event -> removeSelectedAttachments());

        renameAttachmentButton = new JButton("Rename");
        renameAttachmentButton.setFont(bodyFont);
        renameAttachmentButton.setEnabled(false);
        renameAttachmentButton.addActionListener(event -> renameSelectedAttachment());

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setBackground(surfaceBackground);
        actions.add(pasteScreenshotButton);
        actions.add(removeAttachmentButton);
        actions.add(renameAttachmentButton);

        panel.add(title, BorderLayout.NORTH);
        panel.add(listScroll, BorderLayout.CENTER);
        panel.add(actions, BorderLayout.SOUTH);

        return panel;
    }

    private void queueOutlineUpdate() {
        if (outlineListModel == null || notesArea == null) {
            return;
        }
        if (outlineUpdateTimer == null) {
            outlineUpdateTimer = new Timer(250, event -> updateOutlineFromNotes());
            outlineUpdateTimer.setRepeats(false);
        }
        if (outlineUpdateTimer.isRunning()) {
            outlineUpdateTimer.restart();
        } else {
            outlineUpdateTimer.start();
        }
    }

    private void updateOutlineFromNotes() {
        if (outlineListModel == null || notesArea == null) {
            return;
        }
        List<OutlineEntry> entries = extractOutlineEntries(notesArea.getText());
        outlineUpdating = true;
        outlineListModel.clear();
        for (OutlineEntry entry : entries) {
            outlineListModel.addElement(entry);
        }
        outlineUpdating = false;
    }

    private List<OutlineEntry> extractOutlineEntries(String text) {
        List<OutlineEntry> entries = new ArrayList<>();
        if (text == null || text.isEmpty()) {
            return entries;
        }
        String[] lines = text.split("\\r?\\n", -1);
        boolean inFence = false;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.startsWith("```")) {
                inFence = !inFence;
                continue;
            }
            if (inFence) {
                continue;
            }
            if (!trimmed.startsWith("#")) {
                continue;
            }
            int level = 0;
            while (level < trimmed.length() && trimmed.charAt(level) == '#') {
                level++;
            }
            if (level == 0) {
                continue;
            }
            String title = trimmed.substring(level).trim();
            if (title.isEmpty()) {
                continue;
            }
            entries.add(new OutlineEntry(level, title, i + 1));
        }
        return entries;
    }

    private void jumpToOutlineEntry(OutlineEntry entry) {
        if (entry == null || notesArea == null) {
            return;
        }
        if (notesEditorTabs != null) {
            notesEditorTabs.setSelectedIndex(0);
        }
        try {
            int offset = notesArea.getLineStartOffset(Math.max(0, entry.lineNumber - 1));
            notesArea.requestFocusInWindow();
            notesArea.setCaretPosition(offset);
            Rectangle rect = notesArea.modelToView(offset);
            if (rect != null) {
                notesArea.scrollRectToVisible(rect);
            }
        } catch (BadLocationException ignored) {
            // ignore invalid line offsets
        }
    }

    private JPanel buildCheatsheetPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(appBackground);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(appBackground);
        header.setBorder(BorderFactory.createEmptyBorder(12, 12, 4, 12));

        JLabel title = new JLabel("Cheatsheet");
        title.setFont(headerFont);
        title.setForeground(accentColor);

        JLabel subtitle = new JLabel("Quick reference for common vulnerability classes.");
        subtitle.setFont(bodyFont);
        subtitle.setForeground(mutedText);

        JPanel textPanel = new JPanel();
        textPanel.setLayout(new BoxLayout(textPanel, BoxLayout.Y_AXIS));
        textPanel.setBackground(appBackground);
        textPanel.add(title);
        textPanel.add(Box.createVerticalStrut(4));
        textPanel.add(subtitle);

        header.add(textPanel, BorderLayout.WEST);
        panel.add(header, BorderLayout.NORTH);

        JPanel listPanel = new JPanel();
        listPanel.setLayout(new BoxLayout(listPanel, BoxLayout.Y_AXIS));
        listPanel.setBackground(appBackground);

        for (CheatsheetEntry entry : CheatsheetLibrary.getEntries()) {
            JPanel card = buildCheatsheetCard(entry);
            card.setAlignmentX(Component.LEFT_ALIGNMENT);
            listPanel.add(card);
            listPanel.add(Box.createVerticalStrut(10));
        }

        JScrollPane scrollPane = new JScrollPane(listPanel);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildCheatsheetCard(CheatsheetEntry entry) {
        JPanel card = new JPanel(new BorderLayout(0, 6));
        card.setBackground(surfaceBackground);
        card.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(10, 12, 12, 12)
        ));

        String rawTitle = entry.getTitle();
        String displayTitle = truncateTitle(rawTitle, 56);
        JLabel title = new JLabel(displayTitle);
        title.setFont(sectionFont);
        title.setForeground(accentColor);
        if (!displayTitle.equals(rawTitle)) {
            title.setToolTipText(rawTitle);
        }
        Dimension titleSize = title.getPreferredSize();
        title.setMinimumSize(new Dimension(0, titleSize.height));

        JButton infoButton = new JButton("i");
        infoButton.setFont(bodyFont);
        infoButton.setMargin(new Insets(2, 8, 2, 8));
        infoButton.setFocusPainted(false);
        infoButton.setForeground(accentColor);
        infoButton.setBackground(blend(surfaceBackground, borderColor, 0.08f));
        infoButton.setBorder(BorderFactory.createLineBorder(borderColor));
        infoButton.setToolTipText("Recon and exploit notes");
        infoButton.addActionListener(event -> showCheatsheetInfo(entry));

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(surfaceBackground);
        header.add(title, BorderLayout.CENTER);
        header.add(infoButton, BorderLayout.EAST);

        JTextArea body = new JTextArea(formatCheatsheetBullets(entry.getBullets()));
        body.setEditable(false);
        body.setFont(bodyFont);
        body.setLineWrap(true);
        body.setWrapStyleWord(true);
        body.setBackground(surfaceBackground);
        body.setBorder(BorderFactory.createEmptyBorder(4, 2, 2, 2));

        card.add(header, BorderLayout.NORTH);
        card.add(body, BorderLayout.CENTER);

        return card;
    }

    private String formatCheatsheetBullets(List<String> bullets) {
        if (bullets == null || bullets.isEmpty()) {
            return "(no notes)";
        }
        StringBuilder sb = new StringBuilder();
        for (String bullet : bullets) {
            sb.append("- ").append(bullet).append("\n");
        }
        return sb.toString().trim();
    }

    private void showCheatsheetInfo(CheatsheetEntry entry) {
        if (entry == null) {
            return;
        }
        showInfoDialog(entry.getTitle(), entry.getIdentify(), entry.getRecon(), entry.getExploit(), null);
    }

    private void showInfoDialog(String title, String identify, String recon, String exploit, List<String> items) {
        String cleanIdentify = stripLeadingLabel(identify, "Identify");
        String cleanRecon = stripLeadingLabel(recon, "Recon");
        String cleanExploit = stripLeadingLabel(exploit, "Exploit");
        boolean hasIdentify = cleanIdentify != null && !cleanIdentify.isEmpty();
        boolean hasRecon = cleanRecon != null && !cleanRecon.isEmpty();
        boolean hasExploit = cleanExploit != null && !cleanExploit.isEmpty();
        boolean hasItems = items != null && !items.isEmpty();

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(appBackground);

        if (title != null && !title.trim().isEmpty()) {
            JLabel header = new JLabel(title);
            header.setFont(headerFont);
            header.setForeground(accentColor);
            header.setAlignmentX(Component.LEFT_ALIGNMENT);
            content.add(header);
            content.add(Box.createVerticalStrut(8));
        }

        if (hasIdentify) {
            content.add(buildInfoSection("Identify", cleanIdentify));
            content.add(Box.createVerticalStrut(8));
        }
        if (hasRecon) {
            content.add(buildInfoSection("Recon", cleanRecon));
            content.add(Box.createVerticalStrut(8));
        }
        if (hasExploit) {
            content.add(buildInfoSection("Exploit", cleanExploit));
            content.add(Box.createVerticalStrut(8));
        }
        if (hasItems) {
            content.add(buildInfoSection("Checklist", formatItems(items)));
        }

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        scroll.setPreferredSize(new Dimension(520, 420));
        scroll.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.getViewport().setBackground(appBackground);
        scroll.setBackground(appBackground);

        String dialogTitle = title == null || title.trim().isEmpty() ? "Info" : title + " info";
        JOptionPane.showMessageDialog(rootPanel, scroll, dialogTitle, JOptionPane.INFORMATION_MESSAGE);
    }

    private JPanel buildInfoSection(String label, String text) {
        JPanel section = new JPanel();
        section.setLayout(new BoxLayout(section, BoxLayout.Y_AXIS));
        section.setBackground(surfaceBackground);
        section.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(8, 10, 8, 10)
        ));
        section.setAlignmentX(Component.LEFT_ALIGNMENT);

        JLabel heading = new JLabel(label);
        heading.setFont(sectionFont);
        heading.setForeground(accentColor);
        heading.setAlignmentX(Component.LEFT_ALIGNMENT);

        JTextArea body = new JTextArea(text == null ? "" : text.trim());
        body.setFont(bodyFont);
        body.setEditable(false);
        body.setLineWrap(true);
        body.setWrapStyleWord(true);
        body.setBackground(surfaceBackground);
        body.setBorder(BorderFactory.createEmptyBorder(4, 0, 0, 0));
        body.setAlignmentX(Component.LEFT_ALIGNMENT);

        section.add(heading);
        section.add(body);
        return section;
    }

    private String stripLeadingLabel(String text, String label) {
        if (text == null) {
            return "";
        }
        String cleaned = text.trim();
        if (cleaned.isEmpty()) {
            return "";
        }
        String lower = cleaned.toLowerCase(Locale.ROOT);
        String labelLower = label.toLowerCase(Locale.ROOT);
        if (lower.startsWith(labelLower)) {
            String rest = cleaned.substring(label.length()).trim();
            if (rest.startsWith(":") || rest.startsWith("-")) {
                rest = rest.substring(1).trim();
            }
            return rest;
        }
        return cleaned;
    }

    private String formatItems(List<String> items) {
        StringBuilder sb = new StringBuilder();
        if (items != null) {
            for (String item : items) {
                if (item == null || item.trim().isEmpty()) {
                    continue;
                }
                sb.append("- ").append(item.trim()).append("\n");
            }
        }
        return sb.toString().trim();
    }

    private JPanel buildOptionsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(appBackground);

        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(appBackground);

        content.add(createOptionsSectionPanel(
            "Targets",
            "Pick an in-scope base domain from scope and site map.",
            buildTargetSelectionContent()
        ));
        content.add(Box.createVerticalStrut(12));
        content.add(createOptionsSectionPanel(
            "Tags & Analytics",
            "Filter targets, export by tag, and review coverage.",
            buildTagsOptionsContent()
        ));
        content.add(Box.createVerticalStrut(12));
        content.add(createOptionsSectionPanel(
            "Hotkeys",
            "Keyboard shortcuts.",
            buildHotkeysContent()
        ));
        content.add(Box.createVerticalStrut(12));
        content.add(createOptionsSectionPanel(
            "Settings",
            "Storage, export, performance, and data management.",
            buildSettingsContent()
        ));

        JScrollPane scrollPane = new JScrollPane(content);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        scrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        scrollPane.getVerticalScrollBar().setUnitIncrement(16);
        scrollPane.getViewport().setBackground(appBackground);

        panel.add(scrollPane, BorderLayout.CENTER);
        return panel;
    }

    private JPanel buildTargetSelectionContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(surfaceBackground);

        targetModel = new DefaultComboBoxModel<>();
        targetCombo = new JComboBox<>(targetModel);
        targetCombo.setPreferredSize(new Dimension(260, 26));
        targetCombo.setFont(bodyFont);
        targetCombo.addItemListener(event -> {
            if (isRefreshingTargets) {
                return;
            }
            if (event.getStateChange() == ItemEvent.SELECTED) {
                String selected = (String) event.getItem();
                if (!NO_TARGET.equals(selected)) {
                    setCurrentTarget(selected);
                }
            }
        });

        refreshTargetsButton = new JButton("Refresh");
        refreshTargetsButton.setFont(bodyFont);
        refreshTargetsButton.addActionListener(event -> refreshTargets());

        JPanel row = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        row.setBackground(surfaceBackground);
        JLabel targetLabel = new JLabel("Target:");
        targetLabel.setFont(bodyFont);

        row.add(targetLabel);
        row.add(targetCombo);
        row.add(refreshTargetsButton);

        content.add(row);
        content.add(Box.createVerticalStrut(6));

        JLabel hint = new JLabel("Only base domains are shown. Subdomains are excluded.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);
        content.add(hint);

        return content;
    }

    private JPanel buildTagsOptionsContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(surfaceBackground);

        tagFilterEnabledCheck = new JCheckBox("Enable tag filter");
        tagFilterEnabledCheck.setFont(bodyFont);
        tagFilterEnabledCheck.setBackground(surfaceBackground);
        tagFilterEnabledCheck.setSelected(tagFilterEnabled);
        tagFilterEnabledCheck.addItemListener(event -> {
            tagFilterEnabled = tagFilterEnabledCheck.isSelected();
            saveTagFilterSettings();
            refreshTargets();
        });

        tagFilterMatchAllCheck = new JCheckBox("Match all selected tags");
        tagFilterMatchAllCheck.setFont(bodyFont);
        tagFilterMatchAllCheck.setBackground(surfaceBackground);
        tagFilterMatchAllCheck.setSelected(tagFilterMatchAll);
        tagFilterMatchAllCheck.addItemListener(event -> {
            tagFilterMatchAll = tagFilterMatchAllCheck.isSelected();
            saveTagFilterSettings();
            refreshTargets();
        });

        tagFilterListModel = new DefaultListModel<>();
        tagFilterList = new JList<>(tagFilterListModel);
        tagFilterList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        tagFilterList.setVisibleRowCount(6);
        tagFilterList.setFont(bodyFont);
        tagFilterList.setBackground(surfaceBackground);
        tagFilterList.addListSelectionListener(event -> {
            if (event.getValueIsAdjusting() || isLoadingState) {
                return;
            }
            activeTagFilters.clear();
            activeTagFilters.addAll(tagFilterList.getSelectedValuesList());
            saveTagFilterSettings();
            refreshTargets();
        });

        rebuildTagFilterModel(new TreeSet<>(activeTagFilters));

        JScrollPane filterScroll = new JScrollPane(tagFilterList);
        filterScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        JPanel filterPanel = new JPanel();
        filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));
        filterPanel.setBackground(surfaceBackground);
        filterPanel.add(tagFilterEnabledCheck);
        filterPanel.add(tagFilterMatchAllCheck);
        filterPanel.add(Box.createVerticalStrut(6));
        JLabel filterLabel = new JLabel("Filter tags:");
        filterLabel.setFont(bodyFont);
        filterLabel.setForeground(mutedText);
        filterPanel.add(filterLabel);
        filterPanel.add(Box.createVerticalStrut(4));
        filterPanel.add(filterScroll);

        JPanel filterCard = createOptionsSubsection(
            "Filters",
            "Show only targets that match selected tags.",
            filterPanel
        );

        exportPathField = new JTextField(28);
        exportPathField.setFont(bodyFont);
        exportPathField.setText(exportPath);
        exportPathField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateExportPathFromUi));

        exportUseFilterCheck = new JCheckBox("Use current tag filter");
        exportUseFilterCheck.setFont(bodyFont);
        exportUseFilterCheck.setBackground(surfaceBackground);
        exportUseFilterCheck.setSelected(true);

        exportButton = new JButton("Export Markdown");
        exportButton.setFont(bodyFont);
        exportButton.addActionListener(event -> exportNotesByTag());

        JPanel exportRow = createLabeledRow("Export path:", exportPathField);

        JPanel exportActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        exportActions.setBackground(surfaceBackground);
        exportActions.add(exportUseFilterCheck);
        exportActions.add(exportButton);

        JPanel exportPanel = new JPanel();
        exportPanel.setLayout(new BoxLayout(exportPanel, BoxLayout.Y_AXIS));
        exportPanel.setBackground(surfaceBackground);
        exportPanel.add(exportRow);
        exportPanel.add(Box.createVerticalStrut(6));
        exportPanel.add(exportActions);

        JPanel exportCard = createOptionsSubsection(
            "Export by tag",
            "Export notes grouped by tag.",
            exportPanel
        );

        tagAnalyticsArea = new JTextArea(10, 40);
        tagAnalyticsArea.setFont(monoFont);
        tagAnalyticsArea.setEditable(false);
        tagAnalyticsArea.setLineWrap(true);
        tagAnalyticsArea.setWrapStyleWord(true);
        tagAnalyticsArea.setBackground(surfaceBackground);
        tagAnalyticsArea.setText(buildTagAnalyticsReport());

        JScrollPane analyticsScroll = new JScrollPane(tagAnalyticsArea);
        analyticsScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        refreshAnalyticsButton = new JButton("Refresh Analytics");
        refreshAnalyticsButton.setFont(bodyFont);
        refreshAnalyticsButton.addActionListener(event -> tagAnalyticsArea.setText(buildTagAnalyticsReport()));

        JPanel analyticsPanel = new JPanel();
        analyticsPanel.setLayout(new BoxLayout(analyticsPanel, BoxLayout.Y_AXIS));
        analyticsPanel.setBackground(surfaceBackground);
        analyticsPanel.add(analyticsScroll);
        analyticsPanel.add(Box.createVerticalStrut(6));
        analyticsPanel.add(refreshAnalyticsButton);

        JPanel analyticsCard = createOptionsSubsection(
            "Analytics",
            "Snapshot of tag coverage by target.",
            analyticsPanel
        );

        content.add(filterCard);
        content.add(Box.createVerticalStrut(10));
        content.add(exportCard);
        content.add(Box.createVerticalStrut(10));
        content.add(analyticsCard);

        return content;
    }

    private JPanel buildHotkeysContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(surfaceBackground);

        JPanel keyRow = createHotkeyRow("Ctrl+F", "Search notes (shows line numbers)");

        JButton openSearchButton = new JButton("Open Search");
        openSearchButton.setFont(bodyFont);
        openSearchButton.addActionListener(event -> showSearchDialog());

        JPanel actions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        actions.setBackground(surfaceBackground);
        actions.add(openSearchButton);

        content.add(keyRow);
        content.add(Box.createVerticalStrut(6));
        content.add(actions);

        return content;
    }

    private JPanel buildSearchOptionsContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(surfaceBackground);

        JLabel hint = new JLabel("Search notes and jump to the matching line.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        JButton openSearchButton = new JButton("Open Search");
        openSearchButton.setFont(bodyFont);
        openSearchButton.addActionListener(event -> showSearchDialog());

        content.add(hint);
        content.add(Box.createVerticalStrut(6));
        content.add(openSearchButton);

        return content;
    }

    private JPanel buildSettingsContent() {
        JPanel content = new JPanel();
        content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
        content.setBackground(surfaceBackground);

        autoSaveCheck = new JCheckBox("Auto-save notes (per target)");
        autoSaveCheck.setFont(bodyFont);
        autoSaveCheck.setBackground(surfaceBackground);
        autoSaveCheck.addItemListener(event -> updateCurrentStateFromUi());
        autoSaveCheck.setEnabled(false);

        storageDirectoryField = new JTextField(26);
        storageDirectoryField.setFont(bodyFont);
        storageDirectoryField.setText(storageDirectory);
        storageDirectoryField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateStorageDirectoryFromUi));

        JPanel storagePanel = new JPanel();
        storagePanel.setLayout(new BoxLayout(storagePanel, BoxLayout.Y_AXIS));
        storagePanel.setBackground(surfaceBackground);
        storagePanel.add(autoSaveCheck);
        storagePanel.add(Box.createVerticalStrut(6));
        storagePanel.add(createLabeledRow("Storage directory:", storageDirectoryField));

        JPanel storageCard = createOptionsSubsection(
            "Storage",
            "Where notes and attachments are stored.",
            storagePanel
        );

        importPathField = new JTextField(28);
        importPathField.setFont(bodyFont);

        JButton importBrowseButton = new JButton("Browse");
        importBrowseButton.setFont(bodyFont);
        importBrowseButton.addActionListener(event -> {
            JFileChooser chooser = new JFileChooser();
            chooser.setFileFilter(new FileNameExtensionFilter("Notes files (.md, .json)", "md", "json"));
            int result = chooser.showOpenDialog(rootPanel);
            if (result == JFileChooser.APPROVE_OPTION && chooser.getSelectedFile() != null) {
                importPathField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        JPanel importPathRow = createLabeledRow("Import file:", importPathField);
        JPanel importPathWithBrowse = new JPanel(new BorderLayout(8, 0));
        importPathWithBrowse.setBackground(surfaceBackground);
        importPathWithBrowse.add(importPathRow, BorderLayout.CENTER);
        importPathWithBrowse.add(importBrowseButton, BorderLayout.EAST);

        importModeCombo = new JComboBox<>(new String[] {
            "Import into current target",
            "Create/merge targets from file"
        });
        importModeCombo.setFont(bodyFont);

        importReplaceCheck = new JCheckBox("Replace existing notes");
        importReplaceCheck.setFont(bodyFont);
        importReplaceCheck.setBackground(surfaceBackground);

        importButton = new JButton("Import");
        importButton.setFont(bodyFont);
        importButton.addActionListener(event -> importNotesFromFile());

        JPanel importActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        importActions.setBackground(surfaceBackground);
        importActions.add(importModeCombo);
        importActions.add(importReplaceCheck);
        importActions.add(importButton);

        JPanel importPanel = new JPanel();
        importPanel.setLayout(new BoxLayout(importPanel, BoxLayout.Y_AXIS));
        importPanel.setBackground(surfaceBackground);
        importPanel.add(importPathWithBrowse);
        importPanel.add(Box.createVerticalStrut(6));
        importPanel.add(importActions);

        JPanel importCard = createOptionsSubsection(
            "Import notes",
            "Import from Markdown or JSON exports.",
            importPanel
        );

        exportSelectedPathField = new JTextField(28);
        exportSelectedPathField.setFont(bodyFont);
        exportSelectedPathField.setText(exportPath);
        exportSelectedPathField.getDocument().addDocumentListener(new SimpleDocumentListener(this::updateExportPathFromUi));

        JPanel exportSelectedRow = createLabeledRow("Export path:", exportSelectedPathField);

        exportTargetsListModel = new DefaultListModel<>();
        exportTargetsList = new JList<>(exportTargetsListModel);
        exportTargetsList.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        exportTargetsList.setVisibleRowCount(6);
        exportTargetsList.setFont(bodyFont);
        exportTargetsList.setBackground(surfaceBackground);

        JScrollPane exportTargetsScroll = new JScrollPane(exportTargetsList);
        exportTargetsScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        refreshExportTargetsButton = new JButton("Refresh Targets");
        refreshExportTargetsButton.setFont(bodyFont);
        refreshExportTargetsButton.addActionListener(event -> refreshExportTargetsList());

        exportFormatCombo = new JComboBox<>(new String[] {"Markdown (.md)", "JSON (.json)"});
        exportFormatCombo.setFont(bodyFont);

        exportSelectedButton = new JButton("Export Selected");
        exportSelectedButton.setFont(bodyFont);
        exportSelectedButton.addActionListener(event -> exportSelectedTargets());

        JPanel exportSelectedActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        exportSelectedActions.setBackground(surfaceBackground);
        exportSelectedActions.add(exportFormatCombo);
        exportSelectedActions.add(refreshExportTargetsButton);
        exportSelectedActions.add(exportSelectedButton);

        JPanel exportPanel = new JPanel();
        exportPanel.setLayout(new BoxLayout(exportPanel, BoxLayout.Y_AXIS));
        exportPanel.setBackground(surfaceBackground);
        exportPanel.add(exportSelectedRow);
        exportPanel.add(Box.createVerticalStrut(6));
        exportPanel.add(exportTargetsScroll);
        exportPanel.add(Box.createVerticalStrut(6));
        exportPanel.add(exportSelectedActions);

        JPanel exportCard = createOptionsSubsection(
            "Export selected targets",
            "Create Markdown or JSON exports from the selected list.",
            exportPanel
        );

        showOutlineCheck = new JCheckBox("Show outline navigator");
        showOutlineCheck.setFont(bodyFont);
        showOutlineCheck.setBackground(surfaceBackground);
        showOutlineCheck.setSelected(showOutline);
        showOutlineCheck.addItemListener(event -> {
            showOutline = showOutlineCheck.isSelected();
            saveLayoutSettings();
            updateOutlineVisibility();
        });

        JLabel outlineHint = new JLabel("Toggle the right-hand heading list in Notes.");
        outlineHint.setFont(bodyFont);
        outlineHint.setForeground(mutedText);

        JPanel interfacePanel = new JPanel();
        interfacePanel.setLayout(new BoxLayout(interfacePanel, BoxLayout.Y_AXIS));
        interfacePanel.setBackground(surfaceBackground);
        interfacePanel.add(showOutlineCheck);
        interfacePanel.add(Box.createVerticalStrut(4));
        interfacePanel.add(outlineHint);

        JPanel interfaceCard = createOptionsSubsection(
            "Interface",
            "Layout preferences for the notes editor.",
            interfacePanel
        );

        memoryUsageLabel = new JLabel("Extension memory (approx): --");
        memoryUsageLabel.setFont(bodyFont);
        memoryUsageLabel.setForeground(mutedText);

        unloadInactiveTargetsCheck = new JCheckBox("Unload inactive targets to reduce RAM");
        unloadInactiveTargetsCheck.setFont(bodyFont);
        unloadInactiveTargetsCheck.setBackground(surfaceBackground);
        unloadInactiveTargetsCheck.setSelected(unloadInactiveTargets);
        unloadInactiveTargetsCheck.addItemListener(event -> {
            unloadInactiveTargets = unloadInactiveTargetsCheck.isSelected();
            savePerformanceSettings();
            if (unloadInactiveTargets) {
                unloadInactiveTargetStates();
            }
            updateMemoryUsageLabel();
        });

        JPanel performancePanel = new JPanel();
        performancePanel.setLayout(new BoxLayout(performancePanel, BoxLayout.Y_AXIS));
        performancePanel.setBackground(surfaceBackground);
        performancePanel.add(memoryUsageLabel);
        performancePanel.add(Box.createVerticalStrut(6));
        performancePanel.add(unloadInactiveTargetsCheck);

        JPanel performanceCard = createOptionsSubsection(
            "Performance",
            "Lightweight memory controls for long engagements.",
            performancePanel
        );

        deleteTargetDataButton = new JButton("Delete selected target data");
        deleteTargetDataButton.setFont(bodyFont);
        deleteTargetDataButton.addActionListener(event -> {
            if (currentTarget == null) {
                if (callbacks != null) {
                    callbacks.issueAlert("No target selected.");
                }
                return;
            }
            String message = "Delete stored data for \"" + currentTarget + "\"?";
            int result = JOptionPane.showConfirmDialog(rootPanel, message, "Delete Target Data",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (result == JOptionPane.YES_OPTION) {
                deleteTargetData(currentTarget);
            }
        });

        clearAllDataButton = new JButton("Clear all data");
        clearAllDataButton.setFont(bodyFont);
        clearAllDataButton.addActionListener(event -> {
            JTextField input = new JTextField(12);
            JPanel prompt = new JPanel(new BorderLayout(6, 6));
            prompt.add(new JLabel("Type DELETE to remove all stored data:"), BorderLayout.NORTH);
            prompt.add(input, BorderLayout.CENTER);
            int result = JOptionPane.showConfirmDialog(rootPanel, prompt, "Clear All Data",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
            if (result != JOptionPane.OK_OPTION) {
                return;
            }
            if (!"DELETE".equals(input.getText().trim())) {
                if (callbacks != null) {
                    callbacks.issueAlert("Confirmation failed. Type DELETE to confirm.");
                }
                return;
            }
            clearAllExtensionData();
        });

        JPanel dataActions = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        dataActions.setBackground(surfaceBackground);
        dataActions.add(deleteTargetDataButton);
        dataActions.add(clearAllDataButton);

        JPanel dataPanel = new JPanel();
        dataPanel.setLayout(new BoxLayout(dataPanel, BoxLayout.Y_AXIS));
        dataPanel.setBackground(surfaceBackground);
        dataPanel.add(dataActions);

        JPanel dataCard = createOptionsSubsection(
            "Data management",
            "Delete stored notes, attachments, and checklists.",
            dataPanel
        );

        content.add(storageCard);
        content.add(Box.createVerticalStrut(10));
        content.add(importCard);
        content.add(Box.createVerticalStrut(10));
        content.add(exportCard);
        content.add(Box.createVerticalStrut(10));
        content.add(interfaceCard);
        content.add(Box.createVerticalStrut(10));
        content.add(performanceCard);
        content.add(Box.createVerticalStrut(10));
        content.add(dataCard);

        refreshExportTargetsList();
        startMemoryUsageTimer();
        return content;
    }

    private JPanel createOptionsSectionPanel(String title, String subtitle, JPanel content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(surfaceBackground);
        Color accentStripe = blend(accentColor, surfaceBackground, 0.85f);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(1, 4, 1, 1, accentStripe),
            BorderFactory.createEmptyBorder(12, 12, 12, 12)
        ));

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(surfaceBackground);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(sectionFont);
        titleLabel.setForeground(accentColor);
        header.add(titleLabel);
        if (subtitle != null && !subtitle.trim().isEmpty()) {
            JLabel subtitleLabel = new JLabel(subtitle);
            subtitleLabel.setFont(bodyFont);
            subtitleLabel.setForeground(mutedText);
            header.add(subtitleLabel);
        }
        header.add(Box.createVerticalStrut(8));

        panel.add(header, BorderLayout.NORTH);
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createOptionsSubsection(String title, String subtitle, JPanel content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(surfaceBackground);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(10, 10, 10, 10)
        ));

        JPanel header = new JPanel();
        header.setLayout(new BoxLayout(header, BoxLayout.Y_AXIS));
        header.setBackground(surfaceBackground);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(sectionFont);
        titleLabel.setForeground(accentColor);
        header.add(titleLabel);
        if (subtitle != null && !subtitle.trim().isEmpty()) {
            JLabel subtitleLabel = new JLabel(subtitle);
            subtitleLabel.setFont(bodyFont);
            subtitleLabel.setForeground(mutedText);
            header.add(subtitleLabel);
        }
        header.add(Box.createVerticalStrut(6));

        panel.add(header, BorderLayout.NORTH);
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createLabeledRow(String labelText, JComponent field) {
        JLabel label = new JLabel(labelText);
        label.setFont(bodyFont);
        Dimension size = label.getPreferredSize();
        label.setPreferredSize(new Dimension(130, size.height));

        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBackground(surfaceBackground);
        row.add(label, BorderLayout.WEST);
        row.add(field, BorderLayout.CENTER);
        return row;
    }

    private JPanel createHotkeyRow(String key, String description) {
        JPanel row = new JPanel(new BorderLayout(8, 0));
        row.setBackground(surfaceBackground);

        JLabel keyLabel = new JLabel(key);
        keyLabel.setFont(monoFont);
        keyLabel.setForeground(accentColor);
        keyLabel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ));

        JLabel descLabel = new JLabel(description);
        descLabel.setFont(bodyFont);
        descLabel.setForeground(mutedText);

        row.add(keyLabel, BorderLayout.WEST);
        row.add(descLabel, BorderLayout.CENTER);
        return row;
    }

    private JPanel createSectionPanel(String title, JPanel content) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(surfaceBackground);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(10, 12, 12, 12)
        ));

        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(sectionFont);
        titleLabel.setForeground(accentColor);
        titleLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));

        panel.add(titleLabel, BorderLayout.NORTH);
        panel.add(content, BorderLayout.CENTER);

        return panel;
    }

    private JPanel createCollapsibleSectionPanel(String title, JPanel content, String key, boolean defaultCollapsed) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBackground(surfaceBackground);
        panel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(borderColor),
            BorderFactory.createEmptyBorder(10, 12, 12, 12)
        ));

        boolean collapsed = isSectionCollapsed(key, defaultCollapsed);
        JLabel titleLabel = new JLabel(title);
        titleLabel.setFont(sectionFont);
        titleLabel.setForeground(accentColor);

        JButton toggle = new JButton(collapsed ? "+" : "-");
        toggle.setFont(bodyFont);
        toggle.setMargin(new Insets(2, 6, 2, 6));
        toggle.setFocusPainted(false);

        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(surfaceBackground);
        header.setBorder(BorderFactory.createEmptyBorder(0, 0, 8, 0));
        header.add(titleLabel, BorderLayout.WEST);
        header.add(toggle, BorderLayout.EAST);

        content.setVisible(!collapsed);
        toggle.addActionListener(event -> {
            boolean nowCollapsed = content.isVisible();
            content.setVisible(!nowCollapsed);
            toggle.setText(nowCollapsed ? "+" : "-");
            setSectionCollapsed(key, nowCollapsed);
            panel.revalidate();
            panel.repaint();
        });

        panel.add(header, BorderLayout.NORTH);
        panel.add(content, BorderLayout.CENTER);
        return panel;
    }

    private boolean isSectionCollapsed(String key, boolean defaultCollapsed) {
        if ("tags".equalsIgnoreCase(key)) {
            return tagsCollapsed;
        }
        if ("checklists".equalsIgnoreCase(key)) {
            return checklistsCollapsed;
        }
        return defaultCollapsed;
    }

    private void setSectionCollapsed(String key, boolean collapsed) {
        if ("tags".equalsIgnoreCase(key)) {
            tagsCollapsed = collapsed;
        } else if ("checklists".equalsIgnoreCase(key)) {
            checklistsCollapsed = collapsed;
        }
        saveLayoutSettings();
    }

    private void refreshTargets() {
        isRefreshingTargets = true;
        try {
            Set<String> targets = collectInScopeTargets();
            targets = applyTagFilters(targets);
            targetModel.removeAllElements();

            if (targets.isEmpty()) {
                targetModel.addElement(NO_TARGET);
                targetCombo.setEnabled(false);
                setCurrentTarget(null);
                return;
            }

            for (String target : targets) {
                targetModel.addElement(target);
            }
            targetCombo.setEnabled(true);

            if (currentTarget != null && targets.contains(currentTarget)) {
                targetCombo.setSelectedItem(currentTarget);
            } else if (preferredTarget != null && targets.contains(preferredTarget)) {
                targetCombo.setSelectedItem(preferredTarget);
                setCurrentTarget(preferredTarget);
            } else {
                targetCombo.setSelectedIndex(0);
                setCurrentTarget((String) targetModel.getSelectedItem());
            }
        } finally {
            isRefreshingTargets = false;
        }
        refreshExportTargetsList();
    }

    private Set<String> collectInScopeTargets() {
        Set<String> targets = new TreeSet<>();
        targets.addAll(collectTargetsFromScopeConfig());

        IHttpRequestResponse[] siteMap = callbacks.getSiteMap(null);
        if (siteMap == null) {
            return targets;
        }

        for (IHttpRequestResponse item : siteMap) {
            if (item == null) {
                continue;
            }
            IRequestInfo requestInfo = helpers.analyzeRequest(item);
            if (requestInfo == null) {
                continue;
            }
            URL url = requestInfo.getUrl();
            if (url == null) {
                continue;
            }
            if (callbacks.isInScope(url)) {
                String target = formatTarget(url);
                if (target != null) {
                    targets.add(target);
                }
            }
        }

        targets.add(SAMPLE_TARGET);
        return targets;
    }

    private Set<String> applyTagFilters(Set<String> targets) {
        if (!tagFilterEnabled || activeTagFilters.isEmpty()) {
            return targets;
        }
        Set<String> filtered = new TreeSet<>();
        for (String target : targets) {
            if (targetMatchesTagFilter(target)) {
                filtered.add(target);
            }
        }
        return filtered;
    }

    private boolean targetMatchesTagFilter(String target) {
        Set<String> tags = getTargetTagsQuick(target);
        if (tags.isEmpty()) {
            return false;
        }
        if (tagFilterMatchAll) {
            return tags.containsAll(activeTagFilters);
        }
        for (String tag : activeTagFilters) {
            if (tags.contains(tag)) {
                return true;
            }
        }
        return false;
    }

    private Set<String> getTargetTagsQuick(String target) {
        Set<String> tags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        if (target == null) {
            return tags;
        }
        TargetState state = targetStates.get(target);
        if (state != null && state.loaded) {
            tags.addAll(state.selectedTags);
            return tags;
        }
        tags.addAll(loadTagsFromDisk(target));
        return tags;
    }

    private Set<String> loadTagsFromDisk(String target) {
        Set<String> tags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Path targetDir = getTargetStorageDir(target);
        if (targetDir == null) {
            return tags;
        }
        Path notesFile = targetDir.resolve(NOTES_FILE_NAME);
        if (!Files.exists(notesFile)) {
            return tags;
        }
        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(notesFile)) {
            props.load(in);
        } catch (IOException e) {
            return tags;
        }
        for (String tag : splitList(props.getProperty("tags", ""))) {
            tags.add(tag);
        }
        return tags;
    }

    private Set<String> collectTargetsFromScopeConfig() {
        Set<String> targets = new TreeSet<>();
        if (callbacks == null) {
            return targets;
        }
        String json = callbacks.saveConfigAsJson("project_options.scope");
        if (json == null || json.trim().isEmpty()) {
            return targets;
        }
        Matcher matcher = Pattern.compile("\\\"host\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").matcher(json);
        while (matcher.find()) {
            String rawHost = matcher.group(1);
            String cleaned = normalizeScopeHost(rawHost);
            if (cleaned != null) {
                targets.add(cleaned);
            }
        }
        return targets;
    }

    private String normalizeScopeHost(String rawHost) {
        if (rawHost == null) {
            return null;
        }
        String cleaned = rawHost.trim();
        if (cleaned.isEmpty()) {
            return null;
        }
        cleaned = cleaned.replace("\\\\.", ".");
        cleaned = cleaned.replace("\\Q", "").replace("\\E", "");
        cleaned = cleaned.replace("^", "").replace("$", "");
        cleaned = cleaned.replace(".*", "");
        cleaned = cleaned.replace("*", "");

        if (isIpAddress(cleaned) || "localhost".equalsIgnoreCase(cleaned)) {
            return cleaned.toLowerCase(Locale.ROOT);
        }

        Matcher matcher = Pattern.compile("([A-Za-z0-9-]+\\.)+[A-Za-z0-9-]{2,}").matcher(cleaned);
        String candidate = null;
        while (matcher.find()) {
            candidate = matcher.group();
        }
        if (candidate == null) {
            return null;
        }
        return normalizeTargetHost(candidate);
    }

    private String formatTarget(URL url) {
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return null;
        }
        return normalizeTargetHost(host);
    }

    private String normalizeTargetHost(String host) {
        String cleaned = host.trim().toLowerCase(Locale.ROOT);
        if (cleaned.endsWith(".")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1);
        }
        if (cleaned.isEmpty()) {
            return null;
        }
        if (isIpAddress(cleaned) || "localhost".equals(cleaned)) {
            return cleaned;
        }

        if (publicSuffixList != null && publicSuffixList.isLoaded()) {
            String registrable = publicSuffixList.getRegistrableDomain(cleaned);
            if (registrable != null) {
                return registrable;
            }
        }

        String[] parts = cleaned.split("\\.");
        if (parts.length <= 2) {
            return cleaned;
        }

        String last = parts[parts.length - 1];
        String secondLast = parts[parts.length - 2];
        String lastTwo = secondLast + "." + last;

        if (FALLBACK_MULTI_PART_TLDS.contains(lastTwo)) {
            if (parts.length >= 3) {
                return parts[parts.length - 3] + "." + lastTwo;
            }
        }

        return lastTwo;
    }

    private boolean isIpAddress(String host) {
        if (host.contains(":")) {
            return true;
        }
        return host.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    }

    private void setCurrentTarget(String target) {
        if (Objects.equals(currentTarget, target)) {
            return;
        }
        saveCurrentTargetState();
        persistCurrentTargetState();
        cancelAutoSave();

        currentTarget = target;
        loadCurrentTargetState();
        saveLastTarget();
        unloadInactiveTargetStates();
    }

    private void saveCurrentTargetState() {
        if (currentTarget == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        state.notesText = notesArea.getText();
        state.autoSave = autoSaveCheck.isSelected();
        state.selectedTags.clear();
        if (tagList != null) {
            state.selectedTags.addAll(tagList.getSelectedValuesList());
        }
        state.dirty = true;
    }

    private void loadCurrentTargetState() {
        isLoadingState = true;
        try {
            if (currentTarget == null) {
                notesTargetLabel.setText("Current target: (none)");
                notesArea.setText("");
                notesArea.setEnabled(false);
                notesEditorTabs.setEnabled(false);
                markdownPreview.setText(renderMarkdownToHtml(""));
                previewDirty = false;
                if (outlineList != null) {
                    outlineListModel.clear();
                    outlineList.setEnabled(false);
                }
                if (tagList != null) {
                    tagList.clearSelection();
                    tagList.setEnabled(false);
                }
                if (newTagField != null) {
                    newTagField.setEnabled(false);
                }
                if (addTagButton != null) {
                    addTagButton.setEnabled(false);
                }
                clearChecklistPanel();
                if (addChecklistButton != null) {
                    addChecklistButton.setEnabled(false);
                }

                if (attachmentList != null) {
                    attachmentListModel.clear();
                    attachmentList.setEnabled(false);
                }
                if (pasteScreenshotButton != null) {
                    pasteScreenshotButton.setEnabled(false);
                }
                if (removeAttachmentButton != null) {
                    removeAttachmentButton.setEnabled(false);
                }
                if (renameAttachmentButton != null) {
                    renameAttachmentButton.setEnabled(false);
                }

                autoSaveCheck.setSelected(false);
                autoSaveCheck.setEnabled(false);
                return;
            }

            TargetState state = getOrCreateState(currentTarget);
            loadStateFromDisk(currentTarget, state);

            notesTargetLabel.setText("Current target: " + currentTarget);
            notesArea.setEnabled(true);
            notesEditorTabs.setEnabled(true);
            notesArea.setText(state.notesText);
            resetUndoManager();
            previewDirty = true;
            syncMarkdownPreview();
            if (outlineList != null) {
                outlineList.setEnabled(true);
            }
            updateOutlineFromNotes();
            updateOutlineVisibility();

            if (tagList != null) {
                tagList.setEnabled(true);
                setTagSelection(state.selectedTags);
            }
            if (newTagField != null) {
                newTagField.setEnabled(true);
            }
            if (addTagButton != null) {
                addTagButton.setEnabled(true);
            }
            refreshChecklistPanel(state);
            updateAddChecklistButtonState();

            refreshAttachmentList(state);
            attachmentList.setEnabled(true);
            pasteScreenshotButton.setEnabled(true);
            removeAttachmentButton.setEnabled(true);
            if (renameAttachmentButton != null) {
                renameAttachmentButton.setEnabled(true);
            }

            autoSaveCheck.setEnabled(true);
            autoSaveCheck.setSelected(state.autoSave);
        } finally {
            isLoadingState = false;
        }
    }

    private void updateCurrentStateFromUi() {
        if (isLoadingState || currentTarget == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        state.notesText = notesArea.getText();
        state.autoSave = autoSaveCheck.isSelected();
        state.dirty = true;
        scheduleAutoSave();
    }

    private void updateCurrentTagsFromUi() {
        if (isLoadingState || currentTarget == null || tagList == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        state.selectedTags.clear();
        state.selectedTags.addAll(tagList.getSelectedValuesList());
        refreshChecklistPanel(state);

        updateAddChecklistButtonState();
        state.dirty = true;
        scheduleAutoSave();
    }

    private void updateStorageDirectoryFromUi() {
        if (storageDirectoryField == null) {
            return;
        }
        String updated = safeTrim(storageDirectoryField.getText());
        if (updated.isEmpty()) {
            updated = getDefaultStorageDirectory();
        }
        if (!updated.equals(storageDirectory)) {
            storageDirectory = updated;
            saveStorageDirectory();
        }
    }

    private void updateExportPathFromUi() {
        String updated = "";
        if (exportSelectedPathField != null && exportSelectedPathField.isFocusOwner()) {
            updated = safeTrim(exportSelectedPathField.getText());
        } else if (exportPathField != null && exportPathField.isFocusOwner()) {
            updated = safeTrim(exportPathField.getText());
        } else if (exportSelectedPathField != null && !safeTrim(exportSelectedPathField.getText()).isEmpty()) {
            updated = safeTrim(exportSelectedPathField.getText());
        } else if (exportPathField != null) {
            updated = safeTrim(exportPathField.getText());
        }
        if (updated.isEmpty()) {
            updated = getDefaultExportPath();
        }
        if (!updated.equals(exportPath)) {
            exportPath = updated;
            saveExportPath();
            syncExportPathFields();
        }
    }

    private void syncExportPathFields() {
        if (exportPathField != null && !exportPathField.isFocusOwner()) {
            exportPathField.setText(exportPath);
        }
        if (exportSelectedPathField != null && !exportSelectedPathField.isFocusOwner()) {
            exportSelectedPathField.setText(exportPath);
        }
    }

    private void scheduleAutoSave() {
        if (currentTarget == null || !autoSaveCheck.isSelected()) {
            return;
        }
        if (autoSaveTimer == null) {
            autoSaveTimer = new Timer(900, event -> persistCurrentTargetState());
            autoSaveTimer.setRepeats(false);
        }
        autoSaveTimer.restart();
    }

    private void cancelAutoSave() {
        if (autoSaveTimer != null) {
            autoSaveTimer.stop();
        }
    }

    private void ensureSaveExecutor() {
        if (saveExecutor != null) {
            return;
        }
        ThreadFactory factory = runnable -> {
            Thread thread = new Thread(runnable, "burp-notes-save");
            thread.setDaemon(true);
            return thread;
        };
        saveExecutor = Executors.newSingleThreadExecutor(factory);
    }

    private void shutdownSaveExecutor() {
        if (saveExecutor == null) {
            return;
        }
        saveExecutor.shutdown();
        try {
            if (!saveExecutor.awaitTermination(2, TimeUnit.SECONDS)) {
                saveExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            saveExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void persistCurrentTargetState() {
        if (currentTarget == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        if (!state.dirty) {
            return;
        }
        enqueueSave(currentTarget, state);
    }

    private void enqueueSave(String target, TargetState state) {
        if (target == null || state == null) {
            return;
        }
        TargetStateSnapshot snapshot = TargetStateSnapshot.from(target, state);
        state.dirty = false;
        ensureSaveExecutor();
        saveExecutor.submit(() -> persistTargetSnapshot(snapshot));
    }

    private void persistTargetSnapshot(TargetStateSnapshot snapshot) {
        if (snapshot == null) {
            return;
        }
        Path targetDir = getTargetStorageDir(snapshot.target);
        if (targetDir == null) {
            return;
        }
        try {
            Files.createDirectories(targetDir);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to create storage directory: " + e.getMessage());
            }
            return;
        }

        Properties props = new Properties();
        props.setProperty("notes", encodeBase64(snapshot.notesText));
        props.setProperty("autoSave", Boolean.toString(snapshot.autoSave));
        props.setProperty("tags", String.join("|", snapshot.selectedTags));
        props.setProperty("attachments", String.join("|", snapshot.attachments));
        props.setProperty("checklists", serializeChecklistState(snapshot.checklistStates));
        props.setProperty("customChecklistItems", serializeCustomChecklistItems(snapshot.customChecklistItems));
        props.setProperty("customChecklists", serializeCustomChecklists(snapshot.customChecklists));

        Path notesFile = targetDir.resolve(NOTES_FILE_NAME);
        try (OutputStream out = Files.newOutputStream(notesFile)) {
            props.store(out, "Burp Notes state");
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to save notes: " + e.getMessage());
            }
        }
    }

    private void loadStateFromDisk(String target, TargetState state) {
        if (state.loaded) {
            return;
        }
        Path targetDir = getTargetStorageDir(target);
        if (targetDir == null) {
            state.loaded = true;
            return;
        }
        Path notesFile = targetDir.resolve(NOTES_FILE_NAME);
        if (!Files.exists(notesFile)) {
            if (SAMPLE_TARGET.equalsIgnoreCase(target)) {
                ensureSampleNotes();
            }
            if (!Files.exists(notesFile)) {
                state.loaded = true;
                return;
            }
        }

        Properties props = new Properties();
        try (InputStream in = Files.newInputStream(notesFile)) {
            props.load(in);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to load notes: " + e.getMessage());
            }
            state.loaded = true;
            return;
        }

        state.notesText = decodeBase64(props.getProperty("notes", ""));
        state.autoSave = Boolean.parseBoolean(props.getProperty("autoSave", "false"));

        state.selectedTags.clear();
        for (String tag : splitList(props.getProperty("tags", ""))) {
            state.selectedTags.add(tag);
        }

        state.attachments.clear();
        state.attachments.addAll(splitList(props.getProperty("attachments", "")));
        state.attachmentHashes.clear();

        state.checklistStates.clear();
        state.checklistStates.putAll(deserializeChecklistState(props.getProperty("checklists", "")));

        state.customChecklistItems.clear();
        state.customChecklistItems.putAll(deserializeCustomChecklistItems(props.getProperty("customChecklistItems", "")));

        state.customChecklists.clear();
        state.customChecklists.putAll(deserializeCustomChecklists(props.getProperty("customChecklists", "")));

        state.loaded = true;
        state.dirty = false;
    }

    private void flushAllState() {
        saveCurrentTargetState();
        persistCurrentTargetState();
        saveGlobalTags();
        saveStorageDirectory();
        saveLastTarget();
        saveTagFilterSettings();
        saveExportPath();
        savePerformanceSettings();
    }

    private Path getTargetStorageDir(String target) {
        if (target == null) {
            return null;
        }
        String base = storageDirectory;
        if (base == null || base.trim().isEmpty()) {
            base = getDefaultStorageDirectory();
        }
        String safeTarget = sanitizeTargetName(target);
        Path basePath = resolvePath(base);
        return basePath.resolve(safeTarget);
    }

    private Path getAttachmentsDir(String target) {
        Path targetDir = getTargetStorageDir(target);
        if (targetDir == null) {
            return null;
        }
        return targetDir.resolve(ATTACHMENTS_DIR_NAME);
    }

    private void pasteScreenshot() {
        if (currentTarget == null) {
            return;
        }
        BufferedImage image = readImageFromClipboard();
        if (image == null) {
            if (callbacks != null) {
                callbacks.issueAlert("Clipboard does not contain an image.");
            }
            return;
        }

        Path attachmentsDir = getAttachmentsDir(currentTarget);
        if (attachmentsDir == null) {
            return;
        }
        try {
            Files.createDirectories(attachmentsDir);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to create attachments folder: " + e.getMessage());
            }
            return;
        }

        String imageHash = computeImageHash(image);

        TargetState state = getOrCreateState(currentTarget);
        String existingName = null;
        if (imageHash != null) {
            existingName = findExistingAttachmentByHash(state, attachmentsDir, imageHash);
        }

        String filename;
        if (existingName != null) {
            filename = existingName;
        } else {
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss_SSS").format(new Date());
            filename = "screenshot_" + timestamp + ".png";
            Path filePath = attachmentsDir.resolve(filename);

            try {
                ImageIO.write(image, "png", filePath.toFile());
            } catch (IOException e) {
                if (callbacks != null) {
                    callbacks.printError("Failed to save screenshot: " + e.getMessage());
                }
                return;
            }

            if (imageHash != null) {
                state.attachmentHashes.put(filename, imageHash);
            }
        }

        if (!state.attachments.contains(filename)) {
            state.attachments.add(filename);
        }
        state.dirty = true;
        refreshAttachmentList(state);
        scheduleAutoSave();
        insertAttachmentToken(filename);
    }

    private void removeSelectedAttachments() {
        if (currentTarget == null || attachmentList == null) {
            return;
        }
        List<String> selected = attachmentList.getSelectedValuesList();
        if (selected.isEmpty()) {
            return;
        }

        TargetState state = getOrCreateState(currentTarget);
        Path attachmentsDir = getAttachmentsDir(currentTarget);
        for (String name : selected) {
            state.attachments.remove(name);
            state.attachmentHashes.remove(name);
            if (attachmentsDir != null) {
                try {
                    Files.deleteIfExists(attachmentsDir.resolve(name));
                } catch (IOException e) {
                    if (callbacks != null) {
                        callbacks.printError("Failed to delete attachment: " + e.getMessage());
                    }
                }
            }
        }
        removeAttachmentTokensFromEditor(selected);
        state.dirty = true;
        refreshAttachmentList(state);
        scheduleAutoSave();
    }

    private void renameSelectedAttachment() {
        if (currentTarget == null || attachmentList == null) {
            return;
        }
        List<String> selected = attachmentList.getSelectedValuesList();
        if (selected.size() != 1) {
            if (callbacks != null) {
                callbacks.issueAlert("Select a single attachment to rename.");
            }
            return;
        }

        String oldName = selected.get(0);
        String input = JOptionPane.showInputDialog(rootPanel, "New attachment name:", oldName);
        if (input == null) {
            return;
        }

        String newName = normalizeAttachmentName(input, oldName);
        if (newName == null) {
            if (callbacks != null) {
                callbacks.issueAlert("Invalid attachment name.");
            }
            return;
        }
        if (newName.equals(oldName)) {
            return;
        }

        TargetState state = getOrCreateState(currentTarget);
        if (state.attachments.contains(newName)) {
            if (callbacks != null) {
                callbacks.issueAlert("An attachment with that name already exists.");
            }
            return;
        }

        Path attachmentsDir = getAttachmentsDir(currentTarget);
        if (attachmentsDir == null) {
            return;
        }

        Path source = attachmentsDir.resolve(oldName);
        Path target = attachmentsDir.resolve(newName);
        if (!Files.exists(source)) {
            if (callbacks != null) {
                callbacks.issueAlert("Attachment file not found on disk.");
            }
            return;
        }
        if (Files.exists(target)) {
            if (callbacks != null) {
                callbacks.issueAlert("A file with that name already exists on disk.");
            }
            return;
        }

        try {
            Files.move(source, target);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to rename attachment: " + e.getMessage());
            }
            return;
        }

        int index = state.attachments.indexOf(oldName);
        if (index >= 0) {
            state.attachments.set(index, newName);
        } else {
            state.attachments.add(newName);
        }
        String hash = state.attachmentHashes.remove(oldName);
        if (hash != null) {
            state.attachmentHashes.put(newName, hash);
        }

        replaceAttachmentTokenInEditor(oldName, newName);
        state.dirty = true;
        refreshAttachmentList(state);
        selectAttachmentInList(newName);
        scheduleAutoSave();
    }

    private void refreshAttachmentList(TargetState state) {
        attachmentListModel.clear();
        for (String name : state.attachments) {
            attachmentListModel.addElement(name);
        }
    }

    private BufferedImage readImageFromClipboard() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable data = clipboard.getContents(null);
        if (data == null) {
            return null;
        }
        try {
            if (data.isDataFlavorSupported(DataFlavor.imageFlavor)) {
                Image image = (Image) data.getTransferData(DataFlavor.imageFlavor);
                return toBufferedImage(image);
            }
        } catch (UnsupportedFlavorException | IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to read clipboard image: " + e.getMessage());
            }
        }
        return null;
    }

    private String computeImageHash(BufferedImage image) {
        if (image == null) {
            return null;
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ImageIO.write(image, "png", out);
            return computeSha256(out.toByteArray());
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to hash image: " + e.getMessage());
            }
            return null;
        }
    }

    private String findExistingAttachmentByHash(TargetState state, Path attachmentsDir, String hash) {
        if (state == null || attachmentsDir == null || hash == null) {
            return null;
        }
        for (String name : state.attachments) {
            if (name == null) {
                continue;
            }
            String cached = state.attachmentHashes.get(name);
            if (cached == null) {
                Path filePath = attachmentsDir.resolve(name);
                cached = computeFileHash(filePath);
                if (cached != null) {
                    state.attachmentHashes.put(name, cached);
                }
            }
            if (hash.equals(cached)) {
                return name;
            }
        }
        return null;
    }

    private String computeFileHash(Path file) {
        if (file == null || !Files.exists(file)) {
            return null;
        }
        try (InputStream in = Files.newInputStream(file)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] buffer = new byte[8192];
            int read;
            while ((read = in.read(buffer)) > 0) {
                digest.update(buffer, 0, read);
            }
            return toHex(digest.digest());
        } catch (IOException | NoSuchAlgorithmException e) {
            if (callbacks != null) {
                callbacks.printError("Failed to hash attachment: " + e.getMessage());
            }
            return null;
        }
    }

    private String computeSha256(byte[] data) {
        if (data == null) {
            return null;
        }
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(data);
            return toHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            return null;
        }
    }

    private String toHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean clipboardHasImage() {
        Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
        Transferable data = clipboard.getContents(null);
        return data != null && data.isDataFlavorSupported(DataFlavor.imageFlavor);
    }

    private void installPasteHandler(JComponent component, boolean allowTextFallback) {
        if (component == null) {
            return;
        }
        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        KeyStroke pasteKey = KeyStroke.getKeyStroke(KeyEvent.VK_V, mask);
        Action defaultPaste = allowTextFallback ? component.getActionMap().get(DefaultEditorKit.pasteAction) : null;
        component.getActionMap().put("burpnotes-paste", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                if (clipboardHasImage()) {
                    pasteScreenshot();
                    return;
                }
                if (defaultPaste != null) {
                    defaultPaste.actionPerformed(event);
                }
            }
        });
        component.getInputMap(JComponent.WHEN_FOCUSED).put(pasteKey, "burpnotes-paste");
    }

    private void installUndoRedo(JTextArea area) {
        if (area == null) {
            return;
        }
        UndoManager manager = new UndoManager();
        area.getDocument().addUndoableEditListener(manager);
        notesUndoManager = manager;

        Action undoAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                if (manager.canUndo()) {
                    manager.undo();
                }
            }
        };
        Action redoAction = new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                if (manager.canRedo()) {
                    manager.redo();
                }
            }
        };

        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        area.getActionMap().put("burpnotes-undo", undoAction);
        area.getActionMap().put("burpnotes-redo", redoAction);
        area.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask), "burpnotes-undo");
        area.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, mask), "burpnotes-redo");
        area.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask | KeyEvent.SHIFT_DOWN_MASK), "burpnotes-redo");
    }

    private void resetUndoManager() {
        if (notesUndoManager != null) {
            notesUndoManager.discardAllEdits();
        }
    }

    private BufferedImage toBufferedImage(Image image) {
        if (image instanceof BufferedImage) {
            return (BufferedImage) image;
        }
        int width = Math.max(1, image.getWidth(null));
        int height = Math.max(1, image.getHeight(null));
        BufferedImage bufferedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = bufferedImage.createGraphics();
        g2d.drawImage(image, 0, 0, null);
        g2d.dispose();
        return bufferedImage;
    }

    private void toggleDetach() {
        if (detachedFrame == null) {
            detachNotes();
        } else {
            attachNotes();
        }
    }

    private void detachNotes() {
        if (detachedFrame != null) {
            return;
        }

        notesHostLayout.show(notesHostPanel, "detached");
        notesHostPanel.revalidate();
        notesHostPanel.repaint();

        detachedNotesPanel = buildNotesContentPanel();
        detachedViewState = captureNotesViewState();
        loadCurrentTargetState();

        detachedFrame = new JFrame("Burp Notes");
        detachedFrame.setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        detachedFrame.getContentPane().setLayout(new BorderLayout());
        detachedFrame.getContentPane().add(detachedNotesPanel, BorderLayout.CENTER);
        detachedFrame.pack();
        if (detachedFrame.getWidth() < 900 || detachedFrame.getHeight() < 700) {
            detachedFrame.setSize(900, 700);
        }
        detachedFrame.setLocationRelativeTo(null);
        detachedFrame.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                attachNotes();
            }
        });

        customizeRecursive(detachedFrame.getRootPane());
        detachedFrame.getContentPane().revalidate();
        detachedFrame.getContentPane().repaint();
        detachedFrame.setVisible(true);
        if (detachNotesButton != null) {
            detachNotesButton.setText("Attach");
        }
        if (attachNotesButton != null) {
            attachNotesButton.setEnabled(true);
        }
    }

    private void attachNotes() {
        if (detachedFrame == null) {
            return;
        }
        saveCurrentTargetState();
        persistCurrentTargetState();
        cancelAutoSave();
        isReattaching = true;
        JFrame frame = detachedFrame;
        detachedFrame = null;

        if (detachedNotesPanel != null) {
            frame.getContentPane().remove(detachedNotesPanel);
            detachedNotesPanel = null;
        }
        frame.dispose();

        applyNotesViewState(embeddedViewState);
        detachedViewState = null;
        notesHostLayout.show(notesHostPanel, "content");
        notesHostPanel.revalidate();
        notesHostPanel.repaint();
        if (notesContentPanel != null) {
            notesContentPanel.revalidate();
            notesContentPanel.repaint();
        }
        if (attachNotesButton != null) {
            attachNotesButton.setEnabled(false);
        }
        loadCurrentTargetState();
        isReattaching = false;
    }

    private void reattachNotesPanel() {
        notesHostLayout.show(notesHostPanel, "content");
        notesHostPanel.revalidate();
        notesHostPanel.repaint();
        if (detachNotesButton != null) {
            detachNotesButton.setText("Detach");
        }
    }

    private void setTagSelection(Set<String> tags) {
        if (tagList == null || tagListModel == null) {
            return;
        }
        boolean wasLoading = isLoadingState;
        isLoadingState = true;
        try {
            tagList.clearSelection();
            if (tags == null || tags.isEmpty()) {
                return;
            }

            List<Integer> indices = new ArrayList<>();
            for (int i = 0; i < tagListModel.getSize(); i++) {
                String tag = tagListModel.getElementAt(i);
                if (tags.contains(tag)) {
                    indices.add(i);
                }
            }

            int[] indexArray = new int[indices.size()];
            for (int i = 0; i < indices.size(); i++) {
                indexArray[i] = indices.get(i);
            }

            tagList.setSelectedIndices(indexArray);
        } finally {
            isLoadingState = wasLoading;
        }
    }

    private void setTagFilterSelection(Set<String> tags) {
        if (tagFilterList == null || tagFilterListModel == null) {
            return;
        }
        boolean wasLoading = isLoadingState;
        isLoadingState = true;
        try {
            tagFilterList.clearSelection();
            Set<String> selection = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            if (tags != null) {
                selection.addAll(tags);
            }
            activeTagFilters.clear();
            if (selection.isEmpty()) {
                return;
            }

            List<Integer> indices = new ArrayList<>();
            for (int i = 0; i < tagFilterListModel.getSize(); i++) {
                String tag = tagFilterListModel.getElementAt(i);
                if (selection.contains(tag)) {
                    indices.add(i);
                }
            }

            int[] indexArray = new int[indices.size()];
            for (int i = 0; i < indices.size(); i++) {
                indexArray[i] = indices.get(i);
            }

            tagFilterList.setSelectedIndices(indexArray);
            activeTagFilters.addAll(selection);
        } finally {
            isLoadingState = wasLoading;
        }
    }

    private void initDefaultTags() {
        rebuildTagModel();
    }

    private void rebuildTagModel() {
        if (tagListModel == null) {
            return;
        }
        Set<String> selected = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        if (tagList != null) {
            selected.addAll(tagList.getSelectedValuesList());
        }
        Set<String> filterSelected = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        filterSelected.addAll(activeTagFilters);

        tagListModel.clear();
        for (String tag : globalTags) {
            tagListModel.addElement(tag);
        }

        setTagSelection(selected);
        rebuildTagFilterModel(filterSelected);
    }

    private void rebuildTagFilterModel(Set<String> selection) {
        if (tagFilterListModel == null) {
            return;
        }
        boolean wasLoading = isLoadingState;
        isLoadingState = true;
        try {
            tagFilterListModel.clear();
            for (String tag : globalTags) {
                tagFilterListModel.addElement(tag);
            }
            if (selection != null) {
                setTagFilterSelection(selection);
            }
        } finally {
            isLoadingState = wasLoading;
        }
    }

    private void addNewTag() {
        String cleaned = normalizeTag(newTagField.getText());
        if (cleaned.isEmpty()) {
            return;
        }
        boolean added = globalTags.add(cleaned);
        if (added) {
            saveGlobalTags();
            rebuildTagModel();
        }
        selectTag(cleaned);
        newTagField.setText("");
        updateCurrentTagsFromUi();
    }

    private void selectTag(String tag) {
        if (tagList == null || tagListModel == null || tag == null) {
            return;
        }
        for (int i = 0; i < tagListModel.getSize(); i++) {
            String value = tagListModel.getElementAt(i);
            if (value.equalsIgnoreCase(tag)) {
                tagList.addSelectionInterval(i, i);
                tagList.ensureIndexIsVisible(i);
                break;
            }
        }
    }

    private void refreshChecklistPanel(TargetState state) {
        if (tagChecklistContainer == null) {
            return;
        }
        tagChecklistContainer.removeAll();
        checklistCards.clear();

        if (state == null) {
            JLabel empty = new JLabel("Select tags to see checklists.");
            empty.setFont(bodyFont);
            empty.setForeground(mutedText);
            empty.setAlignmentX(Component.LEFT_ALIGNMENT);
            tagChecklistContainer.add(empty);
            tagChecklistContainer.revalidate();
            tagChecklistContainer.repaint();
            return;
        }

        boolean added = false;
        List<String> orderedTags = getSelectedTagsInUiOrder(state.selectedTags);
        Set<String> seenChecklistKeys = new HashSet<>();
        Set<String> addedCustom = new HashSet<>();
        List<CustomChecklist> customList = new ArrayList<>(state.customChecklists.values());

        for (String tag : orderedTags) {
            String key = normalizeTagKey(tag);
            if (seenChecklistKeys.contains(key)) {
                continue;
            }
            List<String> items = new ArrayList<>(TagLibrary.getChecklistForTag(tag));
            List<String> customItems = state.customChecklistItems.get(key);
            if (customItems != null && !customItems.isEmpty()) {
                items.addAll(customItems);
            }
            items = dedupeChecklistItems(items);
            if (items.isEmpty()) {
                continue;
            }
            TagChecklistState checklistState = state.checklistStates.get(key);
            if (checklistState == null) {
                checklistState = new TagChecklistState();
                state.checklistStates.put(key, checklistState);
            }
            for (String item : items) {
                checklistState.itemStates.putIfAbsent(item, new ChecklistItemState());
            }
            CheatsheetEntry entry = CheatsheetLibrary.getEntryByTitle(tag);
            Set<String> removableItems = new HashSet<>();
            if (customItems != null) {
                for (String customItem : customItems) {
                    if (customItem != null) {
                        removableItems.add(customItem.toLowerCase(Locale.ROOT));
                    }
                }
            }
            final List<String> finalItems = items;
            TagChecklistCard card = new TagChecklistCard(
                tag,
                finalItems,
                checklistState,
                () -> updateChecklistState(key),
                () -> showChecklistInfo(tag, entry, finalItems),
                () -> removeChecklist(key, false, tag),
                false,
                removableItems,
                item -> removeChecklistItem(key, item)
            );
            seenChecklistKeys.add(key);
            checklistCards.put(key, card);
            tagChecklistContainer.add(card);
            tagChecklistContainer.add(Box.createVerticalStrut(8));
            added = true;

            for (int i = customList.size() - 1; i >= 0; i--) {
                CustomChecklist custom = customList.get(i);
                if (custom == null || custom.items.isEmpty()) {
                    continue;
                }
                if (!normalizeTagKey(tag).equals(custom.afterKey)) {
                    continue;
                }
                TagChecklistCard customCard = buildCustomChecklistCard(state, custom);
                if (customCard != null) {
                    checklistCards.put(custom.id, customCard);
                    tagChecklistContainer.add(customCard);
                    tagChecklistContainer.add(Box.createVerticalStrut(8));
                    addedCustom.add(custom.id);
                    added = true;
                }
            }
        }

        for (int i = customList.size() - 1; i >= 0; i--) {
            CustomChecklist custom = customList.get(i);
            if (custom == null || custom.items.isEmpty()) {
                continue;
            }
            if (addedCustom.contains(custom.id)) {
                continue;
            }
            TagChecklistCard customCard = buildCustomChecklistCard(state, custom);
            if (customCard != null) {
                checklistCards.put(custom.id, customCard);
                tagChecklistContainer.add(customCard);
                tagChecklistContainer.add(Box.createVerticalStrut(8));
                added = true;
            }
        }

        if (!added) {
            JLabel empty = new JLabel("No checklists yet. Select tags or use Add Checklist.");
            empty.setFont(bodyFont);
            empty.setForeground(mutedText);
            empty.setAlignmentX(Component.LEFT_ALIGNMENT);
            tagChecklistContainer.add(empty);
        }

        tagChecklistContainer.revalidate();
        tagChecklistContainer.repaint();
    }

    private List<String> getSelectedTagsInUiOrder(Set<String> selectedTags) {
        List<String> ordered = new ArrayList<>();
        if (selectedTags == null || selectedTags.isEmpty()) {
            return ordered;
        }
        Set<String> selectedLower = new HashSet<>();
        for (String tag : selectedTags) {
            if (tag != null) {
                selectedLower.add(tag.toLowerCase(Locale.ROOT));
            }
        }
        if (tagListModel != null) {
            for (int i = 0; i < tagListModel.getSize(); i++) {
                String tag = tagListModel.getElementAt(i);
                if (tag != null && selectedLower.contains(tag.toLowerCase(Locale.ROOT))) {
                    ordered.add(tag);
                }
            }
        }
        if (ordered.isEmpty()) {
            ordered.addAll(selectedTags);
        }
        return ordered;
    }

    private TagChecklistCard buildCustomChecklistCard(TargetState state, CustomChecklist custom) {
        if (custom == null || custom.items == null || custom.items.isEmpty()) {
            return null;
        }
        List<String> items = dedupeChecklistItems(custom.items);
        if (items.isEmpty()) {
            return null;
        }
        TagChecklistState checklistState = state.checklistStates.get(custom.id);
        if (checklistState == null) {
            checklistState = new TagChecklistState();
            state.checklistStates.put(custom.id, checklistState);
        }
        for (String item : items) {
            checklistState.itemStates.putIfAbsent(item, new ChecklistItemState());
        }
        CheatsheetEntry entry = CheatsheetLibrary.getEntryByTitle(custom.title);
        return new TagChecklistCard(
            custom.title,
            items,
            checklistState,
            () -> updateChecklistState(custom.id),
            () -> showChecklistInfo(custom.title, entry, items),
            () -> removeChecklist(custom.id, true, custom.title),
            true,
            new HashSet<>(),
            null
        );
    }

    private void clearChecklistPanel() {
        if (tagChecklistContainer == null) {
            return;
        }
        tagChecklistContainer.removeAll();
        JLabel empty = new JLabel("Select tags to see checklists.");
        empty.setFont(bodyFont);
        empty.setForeground(mutedText);
        empty.setAlignmentX(Component.LEFT_ALIGNMENT);
        tagChecklistContainer.add(empty);
        tagChecklistContainer.revalidate();
        tagChecklistContainer.repaint();
    }

    private void updateChecklistState(String tagKey) {
        if (currentTarget == null || tagKey == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        TagChecklistCard card = checklistCards.get(tagKey);
        if (card == null) {
            return;
        }
        TagChecklistState checklistState = state.checklistStates.get(tagKey);
        if (checklistState == null) {
            checklistState = new TagChecklistState();
            state.checklistStates.put(tagKey, checklistState);
        }
        checklistState.collapsed = card.isCollapsed();
        checklistState.itemStates.clear();
        checklistState.itemStates.putAll(card.getItemStates());
        state.dirty = true;
        scheduleAutoSave();
    }

    private void updateAddChecklistButtonState() {
        if (addChecklistButton == null) {
            return;
        }
        boolean hasTarget = currentTarget != null;
        boolean hasSelection = tagList != null && !tagList.isSelectionEmpty();
        boolean enabled = hasTarget && hasSelection;
        addChecklistButton.setEnabled(enabled);
        if (addChecklistItemField != null) {
            addChecklistItemField.setEnabled(enabled);
        }
    }

    private void registerSearchHotkey(JComponent component) {
        if (component == null) {
            return;
        }
        KeyStroke shortcut = KeyStroke.getKeyStroke(KeyEvent.VK_F, Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx());
        String actionKey = "search-notes";
        component.getInputMap(JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT).put(shortcut, actionKey);
        component.getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(shortcut, actionKey);
        component.getActionMap().put(actionKey, new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                showSearchDialog();
            }
        });
    }

    private void installGlobalSearchDispatcher() {
        if (searchDispatcherInstalled) {
            return;
        }
        searchDispatcherInstalled = true;
        KeyboardFocusManager.getCurrentKeyboardFocusManager().addKeyEventDispatcher(event -> {
            if (event.getID() != KeyEvent.KEY_PRESSED) {
                return false;
            }
            if (event.getKeyCode() != KeyEvent.VK_F) {
                return false;
            }
            if (!(event.isControlDown() || event.isMetaDown())) {
                return false;
            }
            Component focusOwner = KeyboardFocusManager.getCurrentKeyboardFocusManager().getFocusOwner();
            if (focusOwner == null) {
                return false;
            }
            boolean inMain = rootPanel != null && SwingUtilities.isDescendingFrom(focusOwner, rootPanel);
            boolean inDetached = detachedFrame != null
                && detachedFrame.getRootPane() != null
                && SwingUtilities.isDescendingFrom(focusOwner, detachedFrame.getRootPane());
            if (!inMain && !inDetached) {
                return false;
            }
            showSearchDialog();
            event.consume();
            return true;
        });
    }

    private void showSearchDialog() {
        ensureSearchDialog();
        searchDialog.setLocationRelativeTo(rootPanel);
        searchDialog.setVisible(true);
        searchDialog.toFront();
        if (searchDialogField != null) {
            searchDialogField.requestFocusInWindow();
            searchDialogField.selectAll();
        }
    }

    private void ensureSearchDialog() {
        if (searchDialog != null) {
            return;
        }

        searchResultsModel = new DefaultListModel<>();
        searchResultsList = new JList<>(searchResultsModel);
        searchResultsList.setFont(bodyFont);
        searchResultsList.setBackground(surfaceBackground);
        searchResultsList.setVisibleRowCount(10);
        searchResultsList.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() == 2) {
                    openSelectedSearchResult();
                }
            }
        });
        searchResultsList.addListSelectionListener(event -> {
            if (!event.getValueIsAdjusting() && event.getFirstIndex() == event.getLastIndex() && event.getFirstIndex() >= 0) {
                // no-op, selection handled on double click
            }
        });
        searchResultsList.addKeyListener(new java.awt.event.KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent event) {
                if (event.getKeyCode() == KeyEvent.VK_ENTER) {
                    openSelectedSearchResult();
                }
            }
        });

        JScrollPane resultsScroll = new JScrollPane(searchResultsList);
        resultsScroll.setBorder(BorderFactory.createLineBorder(borderColor));

        searchDialogField = new JTextField(32);
        searchDialogField.setFont(bodyFont);
        searchDialogField.getDocument().addDocumentListener(new SimpleDocumentListener(this::scheduleSearchDialog));

        JLabel hint = new JLabel("Search notes (Ctrl+F). Double-click a result to jump.");
        hint.setFont(bodyFont);
        hint.setForeground(mutedText);

        JPanel top = new JPanel(new BorderLayout(0, 6));
        top.setBackground(surfaceBackground);
        top.add(hint, BorderLayout.NORTH);
        top.add(searchDialogField, BorderLayout.CENTER);

        JPanel content = new JPanel(new BorderLayout(0, 8));
        content.setBackground(surfaceBackground);
        content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
        content.add(top, BorderLayout.NORTH);
        content.add(resultsScroll, BorderLayout.CENTER);

        searchDialog = new JDialog(SwingUtilities.getWindowAncestor(rootPanel), "Search Notes");
        searchDialog.setModal(false);
        searchDialog.setDefaultCloseOperation(WindowConstants.HIDE_ON_CLOSE);
        searchDialog.getContentPane().setLayout(new BorderLayout());
        searchDialog.getContentPane().setBackground(surfaceBackground);
        searchDialog.getContentPane().add(content, BorderLayout.CENTER);
        searchDialog.setSize(new Dimension(520, 360));

        KeyStroke esc = KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0);
        searchDialog.getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW).put(esc, "close-search");
        searchDialog.getRootPane().getActionMap().put("close-search", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent event) {
                searchDialog.setVisible(false);
            }
        });
    }

    private void scheduleSearchDialog() {
        if (searchDialogField == null) {
            return;
        }
        if (searchDialogTimer == null) {
            searchDialogTimer = new Timer(250, event -> executeSearchDialog());
            searchDialogTimer.setRepeats(false);
        }
        searchDialogTimer.restart();
    }

    private void executeSearchDialog() {
        if (searchResultsModel == null) {
            return;
        }
        searchResultsModel.clear();
        String query = safeTrim(searchDialogField != null ? searchDialogField.getText() : "");
        if (query.isEmpty()) {
            return;
        }
        String needle = query.toLowerCase(Locale.ROOT);

        Set<String> targets = collectTargetsForExport(false);
        for (String target : targets) {
            TargetState state = getOrCreateState(target);
            loadStateFromDisk(target, state);
            addSearchResultsForTarget(target, state.notesText, needle);
        }
        unloadInactiveTargetStates();
    }

    private void addSearchResultsForTarget(String target, String notes, String needle) {
        if (notes == null || notes.isEmpty()) {
            return;
        }
        String[] lines = notes.split("\\R", -1);
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (line != null && line.toLowerCase(Locale.ROOT).contains(needle)) {
                searchResultsModel.addElement(new SearchResult(target, i + 1, line));
            }
        }
    }

    private void openSelectedSearchResult() {
        if (searchResultsList == null) {
            return;
        }
        SearchResult result = searchResultsList.getSelectedValue();
        if (result == null) {
            return;
        }
        if (targetCombo != null && targetModel != null && targetModel.getIndexOf(result.target) >= 0) {
            targetCombo.setSelectedItem(result.target);
        }
        SwingUtilities.invokeLater(() -> focusLine(result.lineNumber));
    }

    private void focusLine(int lineNumber) {
        if (notesArea == null) {
            return;
        }
        int targetLine = Math.max(1, lineNumber);
        try {
            if (notesEditorTabs != null) {
                notesEditorTabs.setSelectedIndex(0);
            }
            int start = notesArea.getLineStartOffset(targetLine - 1);
            int end = notesArea.getLineEndOffset(targetLine - 1);
            notesArea.requestFocusInWindow();
            notesArea.select(start, end);
            notesArea.setCaretPosition(start);
        } catch (BadLocationException e) {
            // ignore
        }
    }

    private String resolveChecklistAnchorTag(TargetState state) {
        if (tagList != null && tagListModel != null) {
            int lead = tagList.getLeadSelectionIndex();
            if (lead >= 0 && lead < tagListModel.getSize()) {
                String leadTag = tagListModel.getElementAt(lead);
                if (leadTag != null && !leadTag.trim().isEmpty()) {
                    return leadTag;
                }
            }
            List<String> selected = tagList.getSelectedValuesList();
            if (selected != null && !selected.isEmpty()) {
                return selected.get(0);
            }
        }
        if (state != null) {
            List<String> ordered = getSelectedTagsInUiOrder(state.selectedTags);
            if (!ordered.isEmpty()) {
                return ordered.get(0);
            }
        }
        return null;
    }

    private void addChecklistItem() {
        if (currentTarget == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        String anchorTag = resolveChecklistAnchorTag(state);
        if (anchorTag == null || anchorTag.trim().isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Select a tag to add a checklist item.");
            }
            return;
        }

        if (addChecklistItemField == null) {
            return;
        }

        String item = safeTrim(addChecklistItemField.getText());
        if (item.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Checklist item is required.");
            }
            return;
        }

        String tagKey = normalizeTagKey(anchorTag);
        List<String> existingBase = TagLibrary.getChecklistForTag(anchorTag);
        if (existingBase.stream().anyMatch(entry -> entry.equalsIgnoreCase(item))) {
            if (callbacks != null) {
                callbacks.issueAlert("This checklist item already exists.");
            }
            return;
        }

        List<String> customItems = state.customChecklistItems.computeIfAbsent(tagKey, key -> new ArrayList<>());
        boolean already = false;
        for (String existing : customItems) {
            if (existing.equalsIgnoreCase(item)) {
                already = true;
                break;
            }
        }
        if (already) {
            if (callbacks != null) {
                callbacks.issueAlert("This checklist item already exists.");
            }
            return;
        }

        customItems.add(item);
        TagChecklistState checklistState = state.checklistStates.get(tagKey);
        if (checklistState == null) {
            checklistState = new TagChecklistState();
            state.checklistStates.put(tagKey, checklistState);
        }
        checklistState.itemStates.putIfAbsent(item, new ChecklistItemState());
        state.dirty = true;
        refreshChecklistPanel(state);
        scheduleAutoSave();
        addChecklistItemField.setText("");
    }

    private void showChecklistInfo(String title, CheatsheetEntry entry, List<String> items) {
        String identify = entry != null ? entry.getIdentify() : null;
        String recon = entry != null ? entry.getRecon() : null;
        String exploit = entry != null ? entry.getExploit() : null;
        showInfoDialog(title == null ? "Checklist info" : title, identify, recon, exploit, items);
    }

    private void removeChecklist(String key, boolean isCustom, String title) {
        if (currentTarget == null || key == null) {
            return;
        }
        String message = isCustom
            ? "Remove checklist \"" + title + "\"?"
            : "Remove checklist \"" + title + "\"? This will unselect the tag and hide its checklist.";
        int result = JOptionPane.showConfirmDialog(rootPanel, message, "Remove Checklist", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
        if (result != JOptionPane.YES_OPTION) {
            return;
        }

        TargetState state = getOrCreateState(currentTarget);
        if (isCustom) {
            state.customChecklists.remove(key);
            state.checklistStates.remove(key);
        } else {
            state.selectedTags.remove(title);
            setTagSelection(state.selectedTags);
            state.checklistStates.remove(key);
        }
        state.dirty = true;
        refreshChecklistPanel(state);
        scheduleAutoSave();
    }

    private void removeChecklistItem(String tagKey, String item) {
        if (currentTarget == null || tagKey == null || item == null) {
            return;
        }
        TargetState state = getOrCreateState(currentTarget);
        List<String> customItems = state.customChecklistItems.get(tagKey);
        if (customItems == null || customItems.isEmpty()) {
            return;
        }
        String trimmedItem = item.trim();
        boolean removed = false;
        for (int i = customItems.size() - 1; i >= 0; i--) {
            String existing = customItems.get(i);
            if (existing != null && existing.equalsIgnoreCase(trimmedItem)) {
                customItems.remove(i);
                removed = true;
            }
        }
        if (!removed) {
            return;
        }
        if (customItems.isEmpty()) {
            state.customChecklistItems.remove(tagKey);
        }
        TagChecklistState checklistState = state.checklistStates.get(tagKey);
        if (checklistState != null) {
            String target = trimmedItem;
            String exactKey = null;
            for (String key : checklistState.itemStates.keySet()) {
                if (key != null && key.equalsIgnoreCase(target)) {
                    exactKey = key;
                    break;
                }
            }
            if (exactKey != null) {
                checklistState.itemStates.remove(exactKey);
            }
        }
        state.dirty = true;
        refreshChecklistPanel(state);
        scheduleAutoSave();
    }

    private String normalizeTag(String tag) {
        if (tag == null) {
            return "";
        }
        return tag.trim();
    }

    private void syncMarkdownPreview() {
        if (markdownPreview == null) {
            return;
        }
        String markdown = notesArea != null ? notesArea.getText() : "";
        try {
            markdownPreview.setText(renderMarkdownToHtml(markdown));
            markdownPreview.setCaretPosition(0);
        } catch (RuntimeException e) {
            if (callbacks != null) {
                callbacks.printError("Preview render failed: " + e.getMessage());
            }
            markdownPreview.setText(renderPreviewError(markdown));
            markdownPreview.setCaretPosition(0);
        }
        previewDirty = false;
    }

    private String renderMarkdownToHtml(String markdown) {
        try {
            StringBuilder html = new StringBuilder();
            String fg = toHex(getUiColor("TextArea.foreground", getUiColor("Label.foreground", new Color(40, 40, 40))));
            String bg = toHex(surfaceBackground);
            String border = toHex(borderColor);
            String codeBg = toHex(blend(surfaceBackground, borderColor, 0.12f));
            String accent = toHex(accentColor);
            String muted = toHex(mutedText);
            String quoteBg = toHex(blend(surfaceBackground, borderColor, 0.08f));
            String codeBorder = toHex(blend(borderColor, accentColor, 0.15f));
            String tableHeader = toHex(blend(surfaceBackground, borderColor, 0.18f));

            html.append("<html><head><style>")
                .append("body{margin:0;padding:0;background:").append(bg).append(";color:").append(fg)
                .append(";font-family:'Segoe UI',Sans-Serif;font-size:").append(bodyFont.getSize())
                .append("px;line-height:1.7;}")
                .append(".md-body{max-width:980px;margin:0 auto;padding:16px 18px;}")
                .append(".md-body h1{font-size:22px;margin:18px 0 12px 0;padding-bottom:6px;border-bottom:1px solid ").append(border).append(";}")
                .append(".md-body h2{font-size:19px;margin:18px 0 10px 0;padding-bottom:4px;border-bottom:1px solid ").append(border).append(";}")
                .append(".md-body h3{font-size:16px;margin:14px 0 8px 0;}")
                .append(".md-body h4{font-size:14px;margin:12px 0 6px 0;color:").append(accent).append(";}")
                .append(".md-body p{margin:8px 0;}")
                .append(".md-body ul,.md-body ol{margin:8px 0 8px 22px;}")
                .append(".md-body li{margin:4px 0;}")
                .append(".md-hr{border:0;border-top:1px solid ").append(border).append(";margin:12px 0;}")
                .append("blockquote{margin:10px 0;padding:8px 12px;border-left:3px solid ").append(border)
                .append(";background:").append(quoteBg).append(";color:").append(fg).append(";}")
                .append(".md-inline-code{background:").append(codeBg).append(";border:1px solid ").append(codeBorder)
                .append(";border-radius:4px;padding:2px 4px;font-family:Monospaced;color:").append(toHex(syntaxStringColor)).append(";}")
                .append(".md-code-block{margin:10px 0;}")
                .append(".md-code-label{font-size:11px;color:").append(muted).append(";margin:0 0 4px 2px;}")
                .append("pre.md-code{background:").append(codeBg).append(";border:1px solid ").append(codeBorder)
                .append(";padding:10px;border-radius:6px;overflow:auto;line-height:1.45;}")
                .append("code{font-family:Monospaced;}")
                .append("a{color:").append(accent).append(";text-decoration:none;}")
                .append("strong{color:").append(toHex(blend(accentColor, mutedText, 0.2f))).append(";font-weight:600;}")
                .append("em{color:").append(toHex(blend(accentColor, mutedText, 0.4f))).append(";font-style:italic;}")
                .append(".md-table{border-collapse:collapse;width:100%;margin:10px 0;}")
                .append(".md-table th,.md-table td{border:1px solid ").append(border).append(";padding:6px 8px;}")
                .append(".md-table th{background:").append(tableHeader).append(";font-weight:600;}")
                .append(".md-checkbox{display:inline-block;min-width:18px;color:").append(accent).append(";}")
                .append("</style></head><body><div class='md-body'>");

            String[] lines = markdown.split("\\R", -1);
            boolean inCode = false;
            String codeLanguage = "";
            StringBuilder codeBuffer = new StringBuilder();
            boolean inUl = false;
            boolean inOl = false;
            boolean inBlockquote = false;

            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                String trimmed = line.trim();

                if (trimmed.startsWith("```")) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (inBlockquote) {
                        html.append("</blockquote>");
                        inBlockquote = false;
                    }
                    if (!inCode) {
                        inCode = true;
                        codeLanguage = trimmed.substring(3).trim();
                        codeBuffer.setLength(0);
                    } else {
                        html.append(renderCodeBlock(codeLanguage, codeBuffer.toString(), border, codeBg));
                        inCode = false;
                        codeLanguage = "";
                    }
                    continue;
                }

                if (inCode) {
                    codeBuffer.append(line).append("\n");
                    continue;
                }

                if (trimmed.isEmpty()) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (inBlockquote) {
                        html.append("</blockquote>");
                        inBlockquote = false;
                    }
                    html.append("<div style='height:6px'></div>");
                    continue;
                }

                if (isAttachmentToken(trimmed)) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (inBlockquote) {
                        html.append("</blockquote>");
                        inBlockquote = false;
                    }
                    html.append(renderAttachmentBlock(trimmed));
                    continue;
                }

                if (isTableHeaderLine(lines, i)) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (inBlockquote) {
                        html.append("</blockquote>");
                        inBlockquote = false;
                    }
                    TableRender table = renderTable(lines, i);
                    html.append(table.html);
                    i = table.nextIndex - 1;
                    continue;
                }

                if (trimmed.equals("---") || trimmed.equals("***")) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    html.append("<hr class='md-hr'>");
                    continue;
                }

                if (trimmed.startsWith("> ")) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (!inBlockquote) {
                        html.append("<blockquote>");
                        inBlockquote = true;
                    }
                    html.append(applyInlineMarkdown(trimmed.substring(2))).append("<br>");
                    continue;
                }

                if (trimmed.startsWith("#")) {
                    closeLists(html, inUl, inOl);
                    inUl = false;
                    inOl = false;
                    if (inBlockquote) {
                        html.append("</blockquote>");
                        inBlockquote = false;
                    }
                    int level = countHeadingLevel(trimmed);
                    String headingText = trimmed.substring(level).trim();
                    html.append("<h")
                        .append(level)
                        .append(">")
                        .append(applyInlineMarkdown(headingText))
                        .append("</h")
                        .append(level)
                        .append(">");
                    continue;
                }

                if (isTaskListItem(trimmed)) {
                    if (inOl) {
                        html.append("</ol>");
                        inOl = false;
                    }
                    if (!inUl) {
                        html.append("<ul>");
                        inUl = true;
                    }
                    String itemText = trimmed.substring(5).trim();
                    boolean checked = trimmed.startsWith("- [x]") || trimmed.startsWith("- [X]") || trimmed.startsWith("* [x]") || trimmed.startsWith("* [X]");
                    html.append("<li><span class='md-checkbox'>")
                        .append(checked ? "☑" : "☐")
                        .append("</span>")
                        .append(applyInlineMarkdown(itemText))
                        .append("</li>");
                    continue;
                }

                if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
                    if (inOl) {
                        html.append("</ol>");
                        inOl = false;
                    }
                    if (!inUl) {
                        html.append("<ul>");
                        inUl = true;
                    }
                    String item = trimmed.substring(2).trim();
                    html.append("<li>").append(applyInlineMarkdown(item)).append("</li>");
                    continue;
                }

                if (isOrderedListItem(trimmed)) {
                    if (inUl) {
                        html.append("</ul>");
                        inUl = false;
                    }
                    if (!inOl) {
                        html.append("<ol>");
                        inOl = true;
                    }
                    String item = trimmed.replaceFirst("^\\d+\\.\\s+", "");
                    html.append("<li>").append(applyInlineMarkdown(item)).append("</li>");
                    continue;
                }

                closeLists(html, inUl, inOl);
                inUl = false;
                inOl = false;
                if (inBlockquote) {
                    html.append("</blockquote>");
                    inBlockquote = false;
                }
                html.append("<p>")
                    .append(applyInlineMarkdown(trimmed))
                    .append("</p>");
            }

            if (inCode) {
                html.append(renderCodeBlock(codeLanguage, codeBuffer.toString(), border, codeBg));
            }
            if (inUl) {
                html.append("</ul>");
            }
            if (inOl) {
                html.append("</ol>");
            }
            if (inBlockquote) {
                html.append("</blockquote>");
            }

            html.append("</div></body></html>");
            return html.toString();
        } catch (RuntimeException e) {
            if (callbacks != null) {
                callbacks.printError("renderMarkdownToHtml failed: " + e.getMessage());
            }
            return renderPreviewError(markdown);
        }
    }

    private String renderCodeBlock(String language, String code, String border, String codeBg) {
        StringBuilder sb = new StringBuilder();
        String label = normalizeLanguageLabel(language);
        sb.append("<div class='md-code-block'>");
        if (!label.isEmpty()) {
            sb.append("<div class='md-code-label'>")
                .append(escapeHtml(label))
                .append("</div>");
        }
        sb.append("<pre class='md-code'>")
            .append("<code>")
            .append(highlightCode(language, code))
            .append("</code></pre></div>");
        return sb.toString();
    }

    private String normalizeLanguageLabel(String language) {
        String normalized = normalizeLanguage(language);
        if (normalized.isEmpty()) {
            return "";
        }
        if ("http".equals(normalized)) {
            return "http";
        }
        if ("csharp".equals(normalized)) {
            return "c#";
        }
        if ("cpp".equals(normalized)) {
            return "c++";
        }
        return normalized;
    }

    private String normalizeLanguage(String language) {
        if (language == null) {
            return "";
        }
        String cleaned = language.trim().toLowerCase(Locale.ROOT);
        if (cleaned.isEmpty()) {
            return "";
        }
        if (cleaned.startsWith("{")) {
            return "";
        }
        if ("py".equals(cleaned) || "python3".equals(cleaned)) {
            return "python";
        }
        if ("sh".equals(cleaned) || "zsh".equals(cleaned) || "shell".equals(cleaned)) {
            return "bash";
        }
        if ("golang".equals(cleaned)) {
            return "go";
        }
        if ("js".equals(cleaned)) {
            return "javascript";
        }
        if ("ts".equals(cleaned)) {
            return "typescript";
        }
        if ("c#".equals(cleaned) || "cs".equals(cleaned)) {
            return "csharp";
        }
        if ("c++".equals(cleaned) || "hpp".equals(cleaned) || "cc".equals(cleaned)) {
            return "cpp";
        }
        if ("yml".equals(cleaned)) {
            return "yaml";
        }
        if ("req".equals(cleaned) || "request".equals(cleaned) || "response".equals(cleaned) || "http".equals(cleaned)) {
            return "http";
        }
        return cleaned;
    }

    private String highlightCode(String language, String code) {
        if (code == null) {
            return "";
        }
        String normalized = normalizeLanguage(language);
        if ("http".equals(normalized)) {
            return highlightHttp(code);
        }
        LanguageProfile profile = LANGUAGE_PROFILES.get(normalized);
        if (profile == null) {
            profile = GENERIC_PROFILE;
        }
        return highlightWithProfile(profile, code);
    }

    private String highlightHttp(String code) {
        StringBuilder sb = new StringBuilder();
        String[] lines = code.split("\\R", -1);
        boolean inHeaders = true;

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            String trimmed = line.trim();
            if (trimmed.isEmpty()) {
                inHeaders = false;
                sb.append("\n");
                continue;
            }

            if (i == 0) {
                Matcher request = Pattern.compile("^(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD|CONNECT|TRACE)\\s+").matcher(trimmed);
                Matcher response = Pattern.compile("^(HTTP/\\d\\.\\d)\\s+(\\d{3})").matcher(trimmed);
                if (request.find()) {
                    sb.append(wrapSpan(syntaxKeywordColor, request.group(1))).append(" ");
                    sb.append(escapeHtml(trimmed.substring(request.end())));
                    sb.append("\n");
                    continue;
                }
                if (response.find()) {
                    sb.append(wrapSpan(syntaxKeywordColor, response.group(1))).append(" ");
                    sb.append(wrapSpan(syntaxNumberColor, response.group(2)));
                    if (response.end() < trimmed.length()) {
                        sb.append(" ").append(escapeHtml(trimmed.substring(response.end()).trim()));
                    }
                    sb.append("\n");
                    continue;
                }
            }

            if (inHeaders) {
                Matcher header = Pattern.compile("^([A-Za-z0-9-]+)(:)(\\s*)(.*)$").matcher(line);
                if (header.matches()) {
                    sb.append(wrapSpan(syntaxHeaderColor, escapeHtml(header.group(1))))
                        .append(escapeHtml(header.group(2)))
                        .append(escapeHtml(header.group(3)))
                        .append(escapeHtml(header.group(4)))
                        .append("\n");
                    continue;
                }
            }

            sb.append(escapeHtml(line)).append("\n");
        }

        return sb.toString();
    }

    private String highlightWithProfile(LanguageProfile profile, String code) {
        StringBuilder sb = new StringBuilder();
        int length = code.length();
        int index = 0;

        while (index < length) {
            String lineComment = matchLineComment(profile, code, index);
            if (lineComment != null) {
                int end = findLineEnd(code, index);
                sb.append(wrapSpan(syntaxCommentColor, escapeHtml(code.substring(index, end))));
                index = end;
                continue;
            }

            if (profile.blockStart != null && code.startsWith(profile.blockStart, index)) {
                int end = code.indexOf(profile.blockEnd, index + profile.blockStart.length());
                if (end < 0) {
                    end = length;
                } else {
                    end += profile.blockEnd.length();
                }
                sb.append(wrapSpan(syntaxCommentColor, escapeHtml(code.substring(index, end))));
                index = end;
                continue;
            }

            char ch = code.charAt(index);
            if (isStringDelimiter(profile, ch)) {
                int end = consumeString(code, index, ch);
                sb.append(wrapSpan(syntaxStringColor, escapeHtml(code.substring(index, end))));
                index = end;
                continue;
            }

            if (isNumberStart(code, index)) {
                int end = consumeNumber(code, index);
                sb.append(wrapSpan(syntaxNumberColor, escapeHtml(code.substring(index, end))));
                index = end;
                continue;
            }

            if (Character.isLetter(ch) || ch == '_' || ch == '$') {
                int end = index + 1;
                while (end < length) {
                    char c = code.charAt(end);
                    if (Character.isLetterOrDigit(c) || c == '_' || c == '$') {
                        end++;
                    } else {
                        break;
                    }
                }
                String word = code.substring(index, end);
                String lookup = word.toLowerCase(Locale.ROOT);
                if (profile.keywords.contains(lookup)) {
                    sb.append(wrapSpan(syntaxKeywordColor, escapeHtml(word)));
                } else {
                    sb.append(escapeHtml(word));
                }
                index = end;
                continue;
            }

            sb.append(escapeHtml(String.valueOf(ch)));
            index++;
        }

        return sb.toString();
    }

    private String matchLineComment(LanguageProfile profile, String code, int index) {
        for (String marker : profile.lineComments) {
            if (code.startsWith(marker, index)) {
                return marker;
            }
        }
        return null;
    }

    private int findLineEnd(String code, int index) {
        int end = code.indexOf('\n', index);
        if (end < 0) {
            return code.length();
        }
        return end;
    }

    private boolean isStringDelimiter(LanguageProfile profile, char ch) {
        return ch == '"' || ch == '\'' || (profile.backtickStrings && ch == '`');
    }

    private int consumeString(String code, int start, char delimiter) {
        int i = start + 1;
        int length = code.length();
        while (i < length) {
            char c = code.charAt(i);
            if (c == '\\' && i + 1 < length) {
                i += 2;
                continue;
            }
            if (c == delimiter) {
                return i + 1;
            }
            i++;
        }
        return length;
    }

    private boolean isNumberStart(String code, int index) {
        char ch = code.charAt(index);
        if (Character.isDigit(ch)) {
            return true;
        }
        if (ch == '.' && index + 1 < code.length() && Character.isDigit(code.charAt(index + 1))) {
            return true;
        }
        return false;
    }

    private int consumeNumber(String code, int start) {
        int i = start;
        int length = code.length();
        boolean hasHex = false;
        while (i < length) {
            char c = code.charAt(i);
            if (Character.isDigit(c) || c == '.' || c == '_' || c == '-') {
                i++;
                continue;
            }
            if ((c == 'x' || c == 'X') && i > start) {
                hasHex = true;
                i++;
                continue;
            }
            if (hasHex && (c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F')) {
                i++;
                continue;
            }
            if (c == 'e' || c == 'E' || c == '+' ) {
                i++;
                continue;
            }
            break;
        }
        return i;
    }

    private String wrapSpan(Color color, String text) {
        return "<span style='color:" + toHex(color) + ";'>" + text + "</span>";
    }

    private void closeLists(StringBuilder html, boolean inUl, boolean inOl) {
        if (inUl) {
            html.append("</ul>");
        }
        if (inOl) {
            html.append("</ol>");
        }
    }

    private boolean isTableHeaderLine(String[] lines, int index) {
        if (lines == null || index < 0 || index + 1 >= lines.length) {
            return false;
        }
        String header = lines[index].trim();
        String divider = lines[index + 1].trim();
        if (header.isEmpty() || divider.isEmpty()) {
            return false;
        }
        if (!header.contains("|") || !divider.contains("|")) {
            return false;
        }
        return isTableDividerLine(divider);
    }

    private boolean isTableDividerLine(String line) {
        if (line == null) {
            return false;
        }
        String cleaned = trimTablePipes(line.trim());
        if (cleaned.isEmpty()) {
            return false;
        }
        String[] parts = cleaned.split("\\|", -1);
        for (String part : parts) {
            String cell = part.trim();
            if (cell.isEmpty()) {
                return false;
            }
            if (!cell.matches(":?-{3,}:?")) {
                return false;
            }
        }
        return true;
    }

    private String trimTablePipes(String line) {
        String trimmed = line.trim();
        if (trimmed.startsWith("|")) {
            trimmed = trimmed.substring(1);
        }
        if (trimmed.endsWith("|")) {
            trimmed = trimmed.substring(0, trimmed.length() - 1);
        }
        return trimmed;
    }

    private List<String> splitTableRow(String line) {
        String cleaned = trimTablePipes(line);
        String[] parts = cleaned.split("\\|", -1);
        List<String> cells = new ArrayList<>();
        for (String part : parts) {
            cells.add(part.trim());
        }
        return cells;
    }

    private List<String> parseTableAlignments(String line, int count) {
        List<String> alignments = new ArrayList<>();
        String cleaned = trimTablePipes(line);
        String[] parts = cleaned.split("\\|", -1);
        for (String part : parts) {
            String cell = part.trim();
            if (cell.startsWith(":") && cell.endsWith(":")) {
                alignments.add("center");
            } else if (cell.endsWith(":")) {
                alignments.add("right");
            } else if (cell.startsWith(":")) {
                alignments.add("left");
            } else {
                alignments.add("left");
            }
        }
        while (alignments.size() < count) {
            alignments.add("left");
        }
        return alignments;
    }

    private boolean isTableRowLine(String line) {
        if (line == null) {
            return false;
        }
        String trimmed = line.trim();
        if (trimmed.isEmpty()) {
            return false;
        }
        return trimmed.contains("|");
    }

    private TableRender renderTable(String[] lines, int startIndex) {
        List<String> headers = splitTableRow(lines[startIndex]);
        List<String> align = parseTableAlignments(lines[startIndex + 1], headers.size());
        List<List<String>> rows = new ArrayList<>();
        int i = startIndex + 2;
        while (i < lines.length && isTableRowLine(lines[i])) {
            rows.add(splitTableRow(lines[i]));
            i++;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("<table class='md-table'>");
        sb.append("<thead><tr>");
        for (int col = 0; col < headers.size(); col++) {
            String cell = col < headers.size() ? headers.get(col) : "";
            sb.append("<th style='text-align:").append(align.get(col)).append(";'>")
                .append(applyInlineMarkdown(cell))
                .append("</th>");
        }
        sb.append("</tr></thead><tbody>");
        for (List<String> row : rows) {
            sb.append("<tr>");
            for (int col = 0; col < headers.size(); col++) {
                String cell = col < row.size() ? row.get(col) : "";
                sb.append("<td style='text-align:").append(align.get(col)).append(";'>")
                    .append(applyInlineMarkdown(cell))
                    .append("</td>");
            }
            sb.append("</tr>");
        }
        sb.append("</tbody></table>");
        return new TableRender(sb.toString(), i);
    }

    private int countHeadingLevel(String line) {
        int level = 0;
        while (level < line.length() && line.charAt(level) == '#') {
            level++;
        }
        return Math.min(level, 6);
    }

    private boolean isOrderedListItem(String line) {
        return line.matches("^\\d+\\.\\s+.*");
    }

    private boolean isTaskListItem(String line) {
        return line.matches("^[*-]\\s+\\[[ xX]\\]\\s+.*");
    }

    private String applyInlineMarkdown(String text) {
        StringBuilder out = new StringBuilder();
        int index = 0;
        while (index < text.length()) {
            int tick = text.indexOf('`', index);
            if (tick < 0) {
                out.append(applyInlineMarkdownSegment(text.substring(index)));
                break;
            }
            if (tick > index) {
                out.append(applyInlineMarkdownSegment(text.substring(index, tick)));
            }
            int endTick = text.indexOf('`', tick + 1);
            if (endTick < 0) {
                out.append(applyInlineMarkdownSegment(text.substring(tick)));
                break;
            }
            String code = text.substring(tick + 1, endTick);
            out.append("<code class='md-inline-code'>")
                .append(escapeHtml(code))
                .append("</code>");
            index = endTick + 1;
        }
        return out.toString();
    }

    private String applyInlineMarkdownSegment(String text) {
        StringBuilder sb = new StringBuilder();
        int index = 0;
        int length = text.length();

        while (index < length) {
            int open = text.indexOf('{', index);
            if (open < 0) {
                sb.append(formatInlineText(text.substring(index)));
                break;
            }
            int close = text.indexOf('}', open + 1);
            if (close < 0) {
                sb.append(formatInlineText(text.substring(index)));
                break;
            }

            if (open > index) {
                sb.append(formatInlineText(text.substring(index, open)));
            }

            String token = text.substring(open + 1, close).trim();
            if (token.isEmpty()) {
                sb.append(formatInlineText(text.substring(open, close + 1)));
            } else {
                sb.append(renderAttachmentInline(token));
            }
            index = close + 1;
        }
        return sb.toString();
    }

    private String formatInlineText(String text) {
        String escaped = escapeHtml(text);
        escaped = escaped.replaceAll("\\*\\*([^*]+)\\*\\*", "<strong>$1</strong>");
        escaped = escaped.replaceAll("\\*([^*]+)\\*\\*", "<em>$1</em>");
        escaped = escaped.replaceAll("\\[(.+?)\\]\\((.+?)\\)", "<a href='$2'>$1</a>");
        return escaped;
    }

    private boolean isAttachmentToken(String line) {
        return line.startsWith("{") && line.endsWith("}") && line.length() > 2;
    }

    private String renderAttachmentBlock(String token) {
        String filename = token.substring(1, token.length() - 1).trim();
        String html = buildAttachmentHtml(filename, true);
        if (html == null) {
            return "<p style='margin:6px 0;'>" + escapeHtml(token) + "</p>";
        }
        return html;
    }

    private String renderAttachmentInline(String filename) {
        String html = buildAttachmentHtml(filename, false);
        if (html == null) {
            return escapeHtml("{" + filename + "}");
        }
        return html;
    }

    private String buildAttachmentHtml(String filename, boolean block) {
        if (filename == null || filename.isEmpty() || filename.contains("/") || filename.contains("\\\\")) {
            return null;
        }
        Path attachmentsDir = getAttachmentsDir(currentTarget);
        if (attachmentsDir == null) {
            return null;
        }
        try {
            Path file = attachmentsDir.resolve(filename);
            if (!Files.exists(file)) {
                return null;
            }
            String border = toHex(borderColor);
            String label = escapeHtml(filename);
            String labelColor = toHex(mutedText);
            String fileUrl = file.toUri().toString();
            if (block) {
                return "<div style='margin:8px 0;'>" +
                    "<img src='" + fileUrl + "' alt='" + label + "' style='max-width:100%; max-height:" + PREVIEW_IMAGE_MAX_HEIGHT + "px; border:1px solid " + border + "; border-radius:6px;'>" +
                    "<div style='margin-top:4px; font-size:11px; color:" + labelColor + ";'>" + label + "</div>" +
                    "</div>";
            }
            return "<span style='display:inline-block; margin-right:6px;'>" +
                "<img src='" + fileUrl + "' alt='" + label + "' style='max-width:" + PREVIEW_INLINE_MAX_WIDTH + "px; max-height:" + PREVIEW_INLINE_MAX_HEIGHT + "px; vertical-align:middle; border:1px solid " + border + "; border-radius:4px;'>" +
                "</span>";
        } catch (RuntimeException e) {
            return null;
        }
    }


    private NotesViewState captureNotesViewState() {
        return new NotesViewState(
            notesArea,
            notesUndoManager,
            markdownPreview,
            notesEditorTabs,
            notesTargetLabel,
            tagListModel,
            tagList,
            newTagField,
            addTagButton,
            tagChecklistContainer,
            tagChecklistScroll,
            addChecklistItemField,
            addChecklistButton,
            attachmentListModel,
            attachmentList,
            pasteScreenshotButton,
            removeAttachmentButton,
            renameAttachmentButton,
            detachNotesButton,
            notesEditorSplit,
            outlinePanel,
            outlinePlaceholder,
            outlineListModel,
            outlineList
        );
    }

    private void applyNotesViewState(NotesViewState state) {
        if (state == null) {
            return;
        }
        notesArea = state.notesArea;
        notesUndoManager = state.notesUndoManager;
        markdownPreview = state.markdownPreview;
        notesEditorTabs = state.notesEditorTabs;
        notesTargetLabel = state.notesTargetLabel;
        tagListModel = state.tagListModel;
        tagList = state.tagList;
        newTagField = state.newTagField;
        addTagButton = state.addTagButton;
        tagChecklistContainer = state.tagChecklistContainer;
        tagChecklistScroll = state.tagChecklistScroll;
        addChecklistItemField = state.addChecklistItemField;
        addChecklistButton = state.addChecklistButton;
        attachmentListModel = state.attachmentListModel;
        attachmentList = state.attachmentList;
        pasteScreenshotButton = state.pasteScreenshotButton;
        removeAttachmentButton = state.removeAttachmentButton;
        renameAttachmentButton = state.renameAttachmentButton;
        detachNotesButton = state.detachNotesButton;
        notesEditorSplit = state.notesEditorSplit;
        outlinePanel = state.outlinePanel;
        outlinePlaceholder = state.outlinePlaceholder;
        outlineListModel = state.outlineListModel;
        outlineList = state.outlineList;
        if (detachNotesButton != null) {
            detachNotesButton.setText(detachedFrame == null ? "Detach" : "Attach");
        }
        updateOutlineVisibility();
    }

    private BufferedImage scaleImage(BufferedImage source, int maxWidth, int maxHeight) {
        int width = source.getWidth();
        int height = source.getHeight();
        if (width <= maxWidth && height <= maxHeight) {
            return source;
        }
        double widthRatio = (double) maxWidth / width;
        double heightRatio = (double) maxHeight / height;
        double scale = Math.min(widthRatio, heightRatio);
        int targetWidth = Math.max(1, (int) Math.round(width * scale));
        int targetHeight = Math.max(1, (int) Math.round(height * scale));

        BufferedImage scaled = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_ARGB);
        Graphics2D g2d = scaled.createGraphics();
        g2d.setRenderingHint(RenderingHints.KEY_INTERPOLATION, RenderingHints.VALUE_INTERPOLATION_BILINEAR);
        g2d.setRenderingHint(RenderingHints.KEY_RENDERING, RenderingHints.VALUE_RENDER_QUALITY);
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2d.drawImage(source, 0, 0, targetWidth, targetHeight, null);
        g2d.dispose();
        return scaled;
    }

    private void insertAttachmentToken(String filename) {
        if (notesArea == null || !notesArea.isEnabled()) {
            return;
        }
        String token = "{" + filename + "}";
        int caret = notesArea.getCaretPosition();
        String text = notesArea.getText();
        boolean needLeading = caret > 0 && text.charAt(caret - 1) != '\n';
        boolean needTrailing = caret < text.length() && text.charAt(caret) != '\n';
        StringBuilder insert = new StringBuilder();
        if (needLeading) {
            insert.append("\n");
        }
        insert.append(token);
        if (needTrailing) {
            insert.append("\n");
        }
        insert.append("\n");
        try {
            notesArea.getDocument().insertString(caret, insert.toString(), null);
        } catch (Exception e) {
            notesArea.setText(text + "\n" + token + "\n");
        }
    }

    private void removeAttachmentTokensFromEditor(List<String> names) {
        if (notesArea == null || names == null || names.isEmpty()) {
            return;
        }
        String original = notesArea.getText();
        String updated = original;
        for (String name : names) {
            if (name == null || name.isEmpty()) {
                continue;
            }
            String tokenPattern = "\\{\\Q" + name + "\\E\\}";
            updated = updated.replaceAll(tokenPattern, "");
        }
        updated = tidyMarkdownWhitespace(updated);
        if (!updated.equals(original)) {
            notesArea.setText(updated);
        }
    }

    private void replaceAttachmentTokenInEditor(String oldName, String newName) {
        if (notesArea == null || oldName == null || newName == null || oldName.isEmpty()) {
            return;
        }
        String original = notesArea.getText();
        String tokenPattern = "\\{\\Q" + oldName + "\\E\\}";
        String updated = original.replaceAll(tokenPattern, "{" + newName + "}");
        if (!updated.equals(original)) {
            notesArea.setText(updated);
        }
    }

    private String tidyMarkdownWhitespace(String text) {
        if (text == null) {
            return "";
        }
        String cleaned = text.replaceAll("[ \\t]+\\n", "\n");
        cleaned = cleaned.replaceAll("\\n{3,}", "\n\n");
        return cleaned;
    }

    private void selectAttachmentInList(String name) {
        if (attachmentList == null || attachmentListModel == null || name == null) {
            return;
        }
        for (int i = 0; i < attachmentListModel.size(); i++) {
            if (name.equals(attachmentListModel.getElementAt(i))) {
                attachmentList.setSelectedIndex(i);
                attachmentList.ensureIndexIsVisible(i);
                break;
            }
        }
    }

    private String normalizeAttachmentName(String input, String currentName) {
        if (input == null) {
            return null;
        }
        String trimmed = input.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        trimmed = trimmed.replaceAll("[\\r\\n\\t]", "");
        if (trimmed.contains("/") || trimmed.contains("\\\\") || trimmed.contains("{") || trimmed.contains("}") || trimmed.contains("|")) {
            return null;
        }
        if (!trimmed.contains(".")) {
            String ext = "";
            if (currentName != null) {
                int dot = currentName.lastIndexOf('.');
                if (dot > 0 && dot < currentName.length() - 1) {
                    ext = currentName.substring(dot);
                }
            }
            trimmed = trimmed + ext;
        }
        return trimmed;
    }

    private String renderPreviewError(String markdown) {
        String bg = toHex(surfaceBackground);
        String fg = toHex(getUiColor("TextArea.foreground", getUiColor("Label.foreground", new Color(40, 40, 40))));
        return "<html><body style='margin:0; padding:10px; background-color:" + bg + "; color:" + fg + ";'>" +
            "<p>Preview failed to render. Showing raw Markdown:</p>" +
            "<pre style='white-space:pre-wrap;'>" + escapeHtml(markdown) + "</pre>" +
            "</body></html>";
    }

    private String escapeHtml(String text) {
        return text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;");
    }

    private Color blend(Color base, Color overlay, float ratio) {
        float clamped = Math.max(0f, Math.min(1f, ratio));
        int r = Math.round(base.getRed() * (1f - clamped) + overlay.getRed() * clamped);
        int g = Math.round(base.getGreen() * (1f - clamped) + overlay.getGreen() * clamped);
        int b = Math.round(base.getBlue() * (1f - clamped) + overlay.getBlue() * clamped);
        return new Color(r, g, b);
    }

    private String toHex(Color color) {
        return String.format("#%02x%02x%02x", color.getRed(), color.getGreen(), color.getBlue());
    }

    private boolean isDarkColor(Color color) {
        double luminance = (0.2126 * color.getRed() + 0.7152 * color.getGreen() + 0.0722 * color.getBlue()) / 255.0;
        return luminance < 0.5;
    }

    private Color getUiColor(String key, Color fallback) {
        Color color = UIManager.getColor(key);
        return color != null ? color : fallback;
    }

    private Font getUiFont(String key, Font fallback) {
        Font font = UIManager.getFont(key);
        return font != null ? font : fallback;
    }

    private String safeTrim(String value) {
        return value == null ? "" : value.trim();
    }

    private Integer parseDividerLocation(String value) {
        String trimmed = safeTrim(value);
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            int parsed = Integer.parseInt(trimmed);
            return parsed > 0 ? parsed : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private String sanitizeTargetName(String target) {
        return target.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private Path resolvePath(String path) {
        Path resolved = Paths.get(path);
        if (resolved.isAbsolute()) {
            return resolved;
        }
        String home = System.getProperty("user.home");
        if (home == null || home.isEmpty()) {
            return resolved.toAbsolutePath();
        }
        return Paths.get(home).resolve(resolved);
    }

    private String getDefaultStorageDirectory() {
        String home = System.getProperty("user.home");
        if (home == null || home.isEmpty()) {
            return ".burp-notes";
        }
        return Paths.get(home, ".burp-notes").toString();
    }

    private String getDefaultExportPath() {
        String base = storageDirectory;
        if (base == null || base.trim().isEmpty()) {
            base = getDefaultStorageDirectory();
        }
        String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
        Path basePath = resolvePath(base);
        Path exportDir = basePath.resolve("exports");
        return exportDir.resolve("burp-notes-export-" + timestamp + ".md").toString();
    }

    private String encodeBase64(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
    }

    private String decodeBase64(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return value;
        }
    }

    private List<String> splitList(String value) {
        List<String> items = new ArrayList<>();
        if (value == null || value.trim().isEmpty()) {
            return items;
        }
        for (String item : value.split("\\|")) {
            String cleaned = item.trim();
            if (!cleaned.isEmpty()) {
                items.add(cleaned);
            }
        }
        return items;
    }

    private String serializeChecklistState(Map<String, TagChecklistState> states) {
        if (states == null || states.isEmpty()) {
            return "";
        }
        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, TagChecklistState> entry : states.entrySet()) {
            String tag = entry.getKey();
            TagChecklistState state = entry.getValue();
            if (tag == null || state == null) {
                continue;
            }
            StringBuilder itemBuilder = new StringBuilder();
            for (Map.Entry<String, ChecklistItemState> item : state.itemStates.entrySet()) {
                if (itemBuilder.length() > 0) {
                    itemBuilder.append(";");
                }
                ChecklistItemState itemState = item.getValue();
                int code;
                if (itemState != null && itemState.notApplicable) {
                    code = 2;
                } else if (itemState != null && itemState.checked) {
                    code = 1;
                } else {
                    code = 0;
                }
                itemBuilder.append(encodeBase64(item.getKey())).append("=").append(code);
            }
            String packed = encodeBase64(tag) + "," + (state.collapsed ? "1" : "0") + "," + itemBuilder;
            entries.add(packed);
        }
        return String.join("|", entries);
    }

    private String serializeCustomChecklists(Map<String, CustomChecklist> checklists) {
        if (checklists == null || checklists.isEmpty()) {
            return "";
        }
        List<String> entries = new ArrayList<>();
        for (CustomChecklist checklist : checklists.values()) {
            if (checklist == null || checklist.id == null || checklist.id.isEmpty()) {
                continue;
            }
            StringBuilder itemBuilder = new StringBuilder();
            for (String item : checklist.items) {
                if (itemBuilder.length() > 0) {
                    itemBuilder.append(";");
                }
                itemBuilder.append(encodeBase64(item));
            }
            String packed = encodeBase64(checklist.id)
                + "," + encodeBase64(checklist.title)
                + "," + encodeBase64(checklist.afterKey)
                + "," + itemBuilder;
            entries.add(packed);
        }
        return String.join("|", entries);
    }

    private String serializeCustomChecklistItems(Map<String, List<String>> itemsByTag) {
        if (itemsByTag == null || itemsByTag.isEmpty()) {
            return "";
        }
        List<String> entries = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : itemsByTag.entrySet()) {
            String tagKey = entry.getKey();
            List<String> items = entry.getValue();
            if (tagKey == null || tagKey.trim().isEmpty() || items == null || items.isEmpty()) {
                continue;
            }
            StringBuilder itemBuilder = new StringBuilder();
            for (String item : items) {
                if (item == null || item.trim().isEmpty()) {
                    continue;
                }
                if (itemBuilder.length() > 0) {
                    itemBuilder.append(";");
                }
                itemBuilder.append(encodeBase64(item.trim()));
            }
            if (itemBuilder.length() == 0) {
                continue;
            }
            entries.add(encodeBase64(tagKey) + "," + itemBuilder);
        }
        return String.join("|", entries);
    }

    private Map<String, TagChecklistState> deserializeChecklistState(String value) {
        Map<String, TagChecklistState> states = new HashMap<>();
        if (value == null || value.trim().isEmpty()) {
            return states;
        }
        String[] entries = value.split("\\|");
        for (String entry : entries) {
            if (entry.trim().isEmpty()) {
                continue;
            }
            String[] parts = entry.split(",", 3);
            if (parts.length < 2) {
                continue;
            }
            String tag = decodeBase64(parts[0]);
            if (tag == null || tag.trim().isEmpty()) {
                continue;
            }
            TagChecklistState state = new TagChecklistState();
            state.collapsed = "1".equals(parts[1]);
            if (parts.length == 3 && !parts[2].isEmpty()) {
                String[] itemParts = parts[2].split(";");
                for (String itemPart : itemParts) {
                    if (itemPart.isEmpty()) {
                        continue;
                    }
                    String[] kv = itemPart.split("=", 2);
                    if (kv.length != 2) {
                        continue;
                    }
                    String key = decodeBase64(kv[0]);
                    if (key == null || key.isEmpty()) {
                        continue;
                    }
                    String raw = kv[1];
                    ChecklistItemState itemState = new ChecklistItemState();
                    if ("2".equals(raw)) {
                        itemState.notApplicable = true;
                        itemState.checked = false;
                    } else {
                        itemState.checked = "1".equals(raw) || "true".equalsIgnoreCase(raw);
                        itemState.notApplicable = false;
                    }
                    state.itemStates.put(key, itemState);
                }
            }
            states.put(normalizeTagKey(tag), state);
        }
        return states;
    }

    private Map<String, CustomChecklist> deserializeCustomChecklists(String value) {
        Map<String, CustomChecklist> checklists = new LinkedHashMap<>();
        if (value == null || value.trim().isEmpty()) {
            return checklists;
        }
        String[] entries = value.split("\\|");
        for (String entry : entries) {
            if (entry.trim().isEmpty()) {
                continue;
            }
            String[] parts = entry.split(",", 4);
            if (parts.length < 2) {
                continue;
            }
            String id = decodeBase64(parts[0]);
            String title = decodeBase64(parts[1]);
            String afterKey = "";
            int itemsIndex = 2;
            if (parts.length == 4) {
                afterKey = decodeBase64(parts[2]);
                itemsIndex = 3;
            }
            if (id == null || id.trim().isEmpty()) {
                continue;
            }
            List<String> items = new ArrayList<>();
            if (parts.length > itemsIndex && !parts[itemsIndex].isEmpty()) {
                for (String itemPart : parts[itemsIndex].split(";")) {
                    if (itemPart.isEmpty()) {
                        continue;
                    }
                    String item = decodeBase64(itemPart);
                    if (item != null && !item.isEmpty()) {
                        items.add(item);
                    }
                }
            }
            String cleanTitle = title == null ? "Checklist" : title;
            checklists.put(id, new CustomChecklist(id, cleanTitle, normalizeTagKey(afterKey), items));
        }
        return checklists;
    }

    private Map<String, List<String>> deserializeCustomChecklistItems(String value) {
        Map<String, List<String>> itemsByTag = new LinkedHashMap<>();
        if (value == null || value.trim().isEmpty()) {
            return itemsByTag;
        }
        String[] entries = value.split("\\|");
        for (String entry : entries) {
            if (entry.trim().isEmpty()) {
                continue;
            }
            String[] parts = entry.split(",", 2);
            if (parts.length < 2) {
                continue;
            }
            String tagKey = decodeBase64(parts[0]);
            if (tagKey == null || tagKey.trim().isEmpty()) {
                continue;
            }
            List<String> items = new ArrayList<>();
            if (!parts[1].isEmpty()) {
                for (String itemPart : parts[1].split(";")) {
                    if (itemPart.isEmpty()) {
                        continue;
                    }
                    String item = decodeBase64(itemPart);
                    if (item != null && !item.isEmpty()) {
                        items.add(item);
                    }
                }
            }
            if (!items.isEmpty()) {
                itemsByTag.put(normalizeTagKey(tagKey), items);
            }
        }
        return itemsByTag;
    }

    private String normalizeTagKey(String tag) {
        if (tag == null) {
            return "";
        }
        return tag.trim().toLowerCase(Locale.ROOT);
    }

    private void exportNotesByTag() {
        updateExportPathFromUi();
        if (exportPath == null || exportPath.trim().isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Export path is empty.");
            }
            return;
        }

        boolean useFilter = exportUseFilterCheck != null && exportUseFilterCheck.isSelected();
        Set<String> targets = collectTargetsForExport(useFilter);
        if (targets.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("No targets available for export.");
            }
            return;
        }

        Map<String, List<TargetExport>> byTag = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        for (String target : targets) {
            TargetState snapshot = new TargetState();
            loadStateFromDisk(target, snapshot);
            if (snapshot.selectedTags.isEmpty()) {
                continue;
            }
            for (String tag : snapshot.selectedTags) {
                byTag.computeIfAbsent(tag, key -> new ArrayList<>())
                    .add(new TargetExport(target, snapshot.notesText));
            }
        }

        if (byTag.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("No tagged notes found to export.");
            }
            return;
        }

        StringBuilder out = new StringBuilder();
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        out.append("# Burp Notes Export\n");
        out.append("Generated: ").append(timestamp).append("\n\n");

        for (Map.Entry<String, List<TargetExport>> entry : byTag.entrySet()) {
            List<TargetExport> exports = entry.getValue();
            out.append("## Tag: ").append(entry.getKey()).append(" (" + exports.size() + " targets)\n\n");
            for (TargetExport targetExport : exports) {
                out.append("### Target: ").append(targetExport.target).append("\n\n");
                String notes = targetExport.notes == null ? "" : targetExport.notes.trim();
                if (notes.isEmpty()) {
                    out.append("(no notes)\n\n");
                } else {
                    out.append(notes).append("\n\n");
                }
                out.append("---\n\n");
            }
        }

        Path output = resolvePath(exportPath);
        try {
            Path parent = output.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(output, out.toString().getBytes(StandardCharsets.UTF_8));
            if (callbacks != null) {
                callbacks.issueAlert("Exported notes to: " + output.toString());
            }
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Export failed: " + e.getMessage());
            }
        }
    }

    private void refreshExportTargetsList() {
        if (exportTargetsListModel == null) {
            return;
        }
        exportTargetsListModel.clear();
        Set<String> targets = collectInScopeTargets();
        for (String target : targets) {
            exportTargetsListModel.addElement(target);
        }
    }

    private void exportSelectedTargets() {
        updateExportPathFromUi();
        if (exportSelectedButton == null || exportTargetsList == null) {
            return;
        }
        List<String> selected = exportTargetsList.getSelectedValuesList();
        if (selected.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Select one or more targets to export.");
            }
            return;
        }

        boolean json = exportFormatCombo != null
            && exportFormatCombo.getSelectedItem() != null
            && exportFormatCombo.getSelectedItem().toString().toLowerCase(Locale.ROOT).contains("json");

        String ext = json ? ".json" : ".md";
        Path output = resolvePath(exportPath);
        if (exportPath.endsWith("/") || exportPath.endsWith("\\") || (Files.exists(output) && Files.isDirectory(output))) {
            String timestamp = new SimpleDateFormat("yyyyMMdd_HHmmss").format(new Date());
            output = output.resolve("burp-notes-targets-" + timestamp + ext);
        } else if (!output.toString().toLowerCase(Locale.ROOT).endsWith(ext)) {
            output = Paths.get(output.toString() + ext);
        }

        String content = json ? buildJsonExport(selected) : buildMarkdownExport(selected);
        try {
            Path parent = output.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(output, content.getBytes(StandardCharsets.UTF_8));
            if (callbacks != null) {
                callbacks.issueAlert("Exported selected targets to: " + output.toString());
            }
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.printError("Export failed: " + e.getMessage());
            }
        }
    }

    private String buildMarkdownExport(List<String> targets) {
        StringBuilder out = new StringBuilder();
        out.append("# Burp Notes Export\n\n");
        out.append("Generated: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n\n");
        for (String target : targets) {
            TargetState state = getOrCreateState(target);
            loadStateFromDisk(target, state);
            out.append("## Target: ").append(target).append("\n\n");

            out.append("### Tags\n");
            if (state.selectedTags.isEmpty()) {
                out.append("- (none)\n\n");
            } else {
                for (String tag : state.selectedTags) {
                    out.append("- ").append(tag).append("\n");
                }
                out.append("\n");
            }

            out.append("### Notes\n");
            if (state.notesText == null || state.notesText.trim().isEmpty()) {
                out.append("(empty)\n\n");
            } else {
                out.append(state.notesText.trim()).append("\n\n");
            }

            out.append("### Checklists\n");
            if (state.selectedTags.isEmpty() && state.customChecklists.isEmpty()) {
                out.append("(none)\n\n");
            } else {
                for (String tag : state.selectedTags) {
                    appendChecklistMarkdown(out, tag, getChecklistItemsForTag(state, tag), state.checklistStates.get(normalizeTagKey(tag)));
                }
                for (CustomChecklist custom : state.customChecklists.values()) {
                    if (custom == null) {
                        continue;
                    }
                    appendChecklistMarkdown(out, custom.title, custom.items, state.checklistStates.get(custom.id));
                }
                out.append("\n");
            }

            out.append("### Attachments\n");
            if (state.attachments.isEmpty()) {
                out.append("- (none)\n\n");
            } else {
                for (String name : state.attachments) {
                    out.append("- ").append(name).append("\n");
                }
                out.append("\n");
            }
        }
        return out.toString();
    }

    private void appendChecklistMarkdown(StringBuilder out, String title, List<String> items, TagChecklistState state) {
        if (title == null || title.trim().isEmpty()) {
            return;
        }
        out.append("#### ").append(title).append("\n");
        if (items == null || items.isEmpty()) {
            out.append("- (none)\n\n");
            return;
        }
        for (String item : items) {
            ChecklistItemState itemState = state != null ? state.itemStates.get(item) : null;
            boolean isNa = itemState != null && itemState.notApplicable;
            boolean checked = itemState != null && itemState.checked && !isNa;
            String label = isNa ? "----- " + item : item;
            out.append("- [").append(checked ? "x" : " ").append("] ").append(label).append("\n");
        }
        out.append("\n");
    }

    private String buildJsonExport(List<String> targets) {
        StringBuilder out = new StringBuilder();
        out.append("{\"generated\":\"")
            .append(escapeJson(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())))
            .append("\",\"targets\":[");
        boolean firstTarget = true;
        for (String target : targets) {
            TargetState state = getOrCreateState(target);
            loadStateFromDisk(target, state);
            if (!firstTarget) {
                out.append(",");
            }
            firstTarget = false;
            out.append("{\"target\":\"").append(escapeJson(target)).append("\"");
            out.append(",\"notes\":\"").append(escapeJson(state.notesText)).append("\"");

            out.append(",\"tags\":[");
            boolean firstTag = true;
            for (String tag : state.selectedTags) {
                if (!firstTag) {
                    out.append(",");
                }
                firstTag = false;
                out.append("\"").append(escapeJson(tag)).append("\"");
            }
            out.append("]");

            out.append(",\"checklists\":[");
            boolean firstChecklist = true;
            for (String tag : state.selectedTags) {
                List<String> items = getChecklistItemsForTag(state, tag);
                if (!firstChecklist) {
                    out.append(",");
                }
                firstChecklist = false;
                appendChecklistJson(out, tag, items, state.checklistStates.get(normalizeTagKey(tag)));
            }
            for (CustomChecklist custom : state.customChecklists.values()) {
                if (custom == null) {
                    continue;
                }
                if (!firstChecklist) {
                    out.append(",");
                }
                firstChecklist = false;
                appendChecklistJson(out, custom.title, custom.items, state.checklistStates.get(custom.id));
            }
            out.append("]");

            out.append(",\"attachments\":[");
            boolean firstAttachment = true;
            for (String name : state.attachments) {
                if (!firstAttachment) {
                    out.append(",");
                }
                firstAttachment = false;
                out.append("\"").append(escapeJson(name)).append("\"");
            }
            out.append("]");

            out.append("}");
        }
        out.append("]}");
        return out.toString();
    }

    private void importNotesFromFile() {
        if (importPathField == null) {
            return;
        }
        String pathText = safeTrim(importPathField.getText());
        if (pathText.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Import path is required.");
            }
            return;
        }
        Path path = resolvePath(pathText);
        if (!Files.exists(path)) {
            if (callbacks != null) {
                callbacks.issueAlert("Import file not found.");
            }
            return;
        }
        String fileName = path.getFileName() != null ? path.getFileName().toString() : path.toString();
        String lower = fileName.toLowerCase(Locale.ROOT);
        boolean isJson = lower.endsWith(".json");
        boolean isMarkdown = lower.endsWith(".md") || lower.endsWith(".markdown");
        if (!isJson && !isMarkdown) {
            if (callbacks != null) {
                callbacks.issueAlert("Only .md or .json files are supported.");
            }
            return;
        }

        String content;
        try {
            content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
        } catch (IOException e) {
            if (callbacks != null) {
                callbacks.issueAlert("Failed to read import file: " + e.getMessage());
            }
            return;
        }
        if (content.trim().isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("Import file is empty.");
            }
            return;
        }

        List<ImportedTarget> imported = isJson ? parseJsonImport(content) : parseMarkdownImport(content);
        boolean intoCurrent = importModeCombo == null || importModeCombo.getSelectedIndex() == 0;
        boolean replace = importReplaceCheck != null && importReplaceCheck.isSelected();

        if (intoCurrent) {
            if (currentTarget == null) {
                if (callbacks != null) {
                    callbacks.issueAlert("Select a target to import into.");
                }
                return;
            }
            String notes = buildNotesForCurrentImport(imported, content);
            if (notes.trim().isEmpty()) {
                if (callbacks != null) {
                    callbacks.issueAlert("No notes found to import.");
                }
                return;
            }
            importNotesIntoCurrent(notes, replace);
            return;
        }

        List<ImportedTarget> targets = new ArrayList<>();
        if (imported != null) {
            for (ImportedTarget target : imported) {
                if (target != null && target.target != null && !target.target.trim().isEmpty()) {
                    targets.add(target);
                }
            }
        }
        if (targets.isEmpty()) {
            if (callbacks != null) {
                callbacks.issueAlert("No target sections found. Use 'Import into current target' for plain notes.");
            }
            return;
        }
        importNotesForTargets(targets, replace);
    }

    private String buildNotesForCurrentImport(List<ImportedTarget> imported, String fallbackContent) {
        if (imported == null || imported.isEmpty()) {
            return fallbackContent == null ? "" : fallbackContent.trim();
        }
        if (imported.size() == 1) {
            ImportedTarget single = imported.get(0);
            if (single != null && single.notes != null && !single.notes.trim().isEmpty()) {
                return single.notes.trim();
            }
            return fallbackContent == null ? "" : fallbackContent.trim();
        }
        StringBuilder sb = new StringBuilder();
        for (ImportedTarget target : imported) {
            if (target == null) {
                continue;
            }
            if (sb.length() > 0) {
                sb.append("\n\n---\n\n");
            }
            if (target.target != null && !target.target.trim().isEmpty()) {
                sb.append("## ").append(target.target.trim()).append("\n\n");
            }
            if (target.notes != null) {
                sb.append(target.notes.trim());
            }
        }
        return sb.toString().trim();
    }

    private void importNotesIntoCurrent(String notes, boolean replace) {
        if (notesArea == null || currentTarget == null) {
            return;
        }
        String existing = notesArea.getText();
        String merged = mergeNotesText(existing, notes, replace);
        notesArea.setText(merged);
        updateCurrentStateFromUi();
        previewDirty = true;
        if (notesEditorTabs != null && notesEditorTabs.getSelectedIndex() == 1) {
            syncMarkdownPreview();
        }
    }

    private void importNotesForTargets(List<ImportedTarget> targets, boolean replace) {
        if (targets == null || targets.isEmpty()) {
            return;
        }
        for (ImportedTarget target : targets) {
            if (target == null || target.target == null || target.target.trim().isEmpty()) {
                continue;
            }
            TargetState state = getOrCreateState(target.target);
            loadStateFromDisk(target.target, state);
            String existing = state.notesText == null ? "" : state.notesText;
            String incoming = target.notes == null ? "" : target.notes;
            state.notesText = mergeNotesText(existing, incoming, replace);
            state.dirty = true;
            enqueueSave(target.target, state);
        }
        refreshTargets();
        updateMemoryUsageLabel();
        unloadInactiveTargetStates();
    }

    private String mergeNotesText(String existing, String incoming, boolean replace) {
        String cleanedIncoming = incoming == null ? "" : incoming.trim();
        if (replace || existing == null || existing.trim().isEmpty()) {
            return cleanedIncoming;
        }
        if (cleanedIncoming.isEmpty()) {
            return existing;
        }
        return existing.trim() + "\n\n---\n\n" + cleanedIncoming;
    }

    private List<ImportedTarget> parseMarkdownImport(String content) {
        List<ImportedTarget> targets = new ArrayList<>();
        if (content == null || content.trim().isEmpty()) {
            return targets;
        }
        String[] lines = content.split("\\R", -1);
        boolean hasNotesSection = false;
        for (String line : lines) {
            if (line == null) {
                continue;
            }
            String trimmed = line.trim();
            if (trimmed.equalsIgnoreCase("### Notes")) {
                hasNotesSection = true;
                break;
            }
        }
        if (!hasNotesSection) {
            targets.add(new ImportedTarget(null, content.trim()));
            return targets;
        }
        ImportedTarget current = null;
        StringBuilder notes = new StringBuilder();
        boolean inNotes = false;
        boolean sawTarget = false;

        for (String line : lines) {
            if (line.startsWith("## ")) {
                if (current != null) {
                    current.notes = notes.toString().trim();
                    targets.add(current);
                }
                current = new ImportedTarget(line.substring(3).trim(), "");
                notes = new StringBuilder();
                inNotes = false;
                sawTarget = true;
                continue;
            }
            if (line.startsWith("### ")) {
                String section = line.substring(4).trim();
                inNotes = "notes".equalsIgnoreCase(section);
                continue;
            }
            if (inNotes && current != null) {
                notes.append(line).append("\n");
            }
        }
        if (current != null) {
            current.notes = notes.toString().trim();
            targets.add(current);
        }

        if (!sawTarget) {
            ImportedTarget single = new ImportedTarget(null, content.trim());
            targets.clear();
            targets.add(single);
        }
        return targets;
    }

    private List<ImportedTarget> parseJsonImport(String content) {
        List<ImportedTarget> targets = new ArrayList<>();
        if (content == null || content.trim().isEmpty()) {
            return targets;
        }
        Object parsed;
        try {
            parsed = new SimpleJsonParser(content).parse();
        } catch (IllegalArgumentException e) {
            if (callbacks != null) {
                callbacks.issueAlert("Invalid JSON: " + e.getMessage());
            }
            return targets;
        }
        if (!(parsed instanceof Map)) {
            return targets;
        }
        Object listObj = ((Map<?, ?>) parsed).get("targets");
        if (!(listObj instanceof List)) {
            return targets;
        }
        for (Object entry : (List<?>) listObj) {
            if (!(entry instanceof Map)) {
                continue;
            }
            Map<?, ?> map = (Map<?, ?>) entry;
            Object targetObj = map.get("target");
            Object notesObj = map.get("notes");
            String target = targetObj instanceof String ? (String) targetObj : "";
            String notes = notesObj instanceof String ? (String) notesObj : "";
            targets.add(new ImportedTarget(target, notes));
        }
        return targets;
    }

    private void appendChecklistJson(StringBuilder out, String title, List<String> items, TagChecklistState state) {
        out.append("{\"title\":\"").append(escapeJson(title)).append("\",\"items\":[");
        if (items != null) {
            boolean first = true;
            for (String item : items) {
                if (!first) {
                    out.append(",");
                }
                first = false;
                ChecklistItemState itemState = state != null ? state.itemStates.get(item) : null;
                boolean isNa = itemState != null && itemState.notApplicable;
                boolean checked = itemState != null && itemState.checked && !isNa;
                out.append("{\"text\":\"").append(escapeJson(item)).append("\",\"checked\":")
                    .append(checked ? "true" : "false").append(",\"na\":")
                    .append(isNa ? "true" : "false").append("}");
            }
        }
        out.append("]}");
    }

    private List<String> getChecklistItemsForTag(TargetState state, String tag) {
        List<String> items = new ArrayList<>(TagLibrary.getChecklistForTag(tag));
        String key = normalizeTagKey(tag);
        List<String> customItems = state.customChecklistItems.get(key);
        if (customItems != null) {
            items.addAll(customItems);
        }
        return dedupeChecklistItems(items);
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\"':
                    sb.append("\\\\\"");
                    break;
                case '\\':
                    sb.append("\\\\");
                    break;
                case '\n':
                    sb.append("\\\\n");
                    break;
                case '\r':
                    sb.append("\\\\r");
                    break;
                case '\t':
                    sb.append("\\\\t");
                    break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    private List<String> dedupeChecklistItems(List<String> items) {
        List<String> deduped = new ArrayList<>();
        if (items == null) {
            return deduped;
        }
        Set<String> seen = new HashSet<>();
        for (String item : items) {
            if (item == null) {
                continue;
            }
            String cleaned = item.trim();
            if (cleaned.isEmpty()) {
                continue;
            }
            String key = cleaned.toLowerCase(Locale.ROOT);
            if (seen.add(key)) {
                deduped.add(cleaned);
            }
        }
        return deduped;
    }

    private Set<String> collectTargetsForExport(boolean useFilter) {
        Set<String> targets = new TreeSet<>();
        targets.addAll(collectInScopeTargets());
        targets.addAll(targetStates.keySet());
        targets.addAll(collectStoredTargets());
        if (useFilter && tagFilterEnabled && !activeTagFilters.isEmpty()) {
            targets = applyTagFilters(targets);
        }
        return targets;
    }

    private Set<String> collectStoredTargets() {
        Set<String> targets = new TreeSet<>();
        String base = storageDirectory;
        if (base == null || base.trim().isEmpty()) {
            base = getDefaultStorageDirectory();
        }
        Path basePath = resolvePath(base);
        if (!Files.isDirectory(basePath)) {
            return targets;
        }
        try (java.util.stream.Stream<Path> stream = Files.list(basePath)) {
            stream.filter(Files::isDirectory).forEach(path -> targets.add(path.getFileName().toString()));
        } catch (IOException e) {
            return targets;
        }
        return targets;
    }

    private String buildTagAnalyticsReport() {
        Set<String> targets = collectTargetsForExport(false);
        Map<String, Integer> tagCounts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        Map<String, Integer> targetTagCounts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);

        for (String target : targets) {
            Set<String> tags = getTargetTagsQuick(target);
            if (tags.isEmpty()) {
                continue;
            }
            targetTagCounts.put(target, tags.size());
            for (String tag : tags) {
                tagCounts.put(tag, tagCounts.getOrDefault(tag, 0) + 1);
            }
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Targets analyzed: ").append(targets.size()).append("\n");
        sb.append("Tagged targets: ").append(targetTagCounts.size()).append("\n\n");

        sb.append("Top Tags:\n");
        List<Map.Entry<String, Integer>> sortedTags = sortByValueDesc(tagCounts);
        int tagLimit = Math.min(10, sortedTags.size());
        for (int i = 0; i < tagLimit; i++) {
            Map.Entry<String, Integer> entry = sortedTags.get(i);
            sb.append("- ").append(entry.getKey()).append(" (").append(entry.getValue()).append(")\n");
        }
        if (sortedTags.isEmpty()) {
            sb.append("- (none)\n");
        }

        sb.append("\nTop Targets by Tag Count:\n");
        List<Map.Entry<String, Integer>> sortedTargets = sortByValueDesc(targetTagCounts);
        int targetLimit = Math.min(8, sortedTargets.size());
        for (int i = 0; i < targetLimit; i++) {
            Map.Entry<String, Integer> entry = sortedTargets.get(i);
            sb.append("- ").append(entry.getKey()).append(" (").append(entry.getValue()).append(" tags)\n");
        }
        if (sortedTargets.isEmpty()) {
            sb.append("- (none)\n");
        }

        sb.append("\nHot Areas:\n");
        List<String> hotTags = new ArrayList<>();
        for (Map.Entry<String, Integer> entry : sortedTags) {
            if (entry.getValue() >= 3) {
                hotTags.add(entry.getKey() + " (" + entry.getValue() + ")");
            }
        }
        if (hotTags.isEmpty()) {
            sb.append("- (none above threshold)\n");
        } else {
            sb.append("- Tags in 3+ targets: ").append(String.join(", ", hotTags)).append("\n");
        }

        return sb.toString();
    }

    private List<Map.Entry<String, Integer>> sortByValueDesc(Map<String, Integer> map) {
        List<Map.Entry<String, Integer>> list = new ArrayList<>(map.entrySet());
        list.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));
        return list;
    }

    private String buildCheatsheetText() {
        StringBuilder sb = new StringBuilder();
        sb.append("BUSINESS LOGIC\n");
        sb.append("  - Map critical flows: signup, checkout, refunds, account changes.\n");
        sb.append("  - Skip steps or change order; ensure server enforces state.\n");
        sb.append("  - Manipulate price/quantity/currency/discount fields (e.g., {\"price\":1}).\n");
        sb.append("  - Reuse coupons or promo codes beyond intended limits.\n");
        sb.append("  - Replay confirmations; look for missing rate limits or idempotency.\n");
        sb.append("  - Trust boundary checks: client-side totals vs server recalculation.\n\n");

        sb.append("SQL INJECTION\n");
        sb.append("  - Test parameters in URL, body, JSON, headers, cookies.\n");
        sb.append("  - Error-based: input ' or \" and watch for SQL errors.\n");
        sb.append("  - Boolean-based: ' AND '1'='1 vs ' AND '1'='2.\n");
        sb.append("  - Time-based: SLEEP(5) / WAITFOR DELAY '0:0:5'.\n");
        sb.append("  - Union-based: UNION SELECT NULL,... to find column count.\n");
        sb.append("  - Check blind indicators: status codes, length, timing.\n\n");

        sb.append("CROSS-SITE SCRIPTING (XSS)\n");
        sb.append("  - Identify context: HTML, attribute, JS string, URL, CSS.\n");
        sb.append("  - Minimal probes: <svg onload=alert(1)> or <img src=x onerror=alert(1)>.\n");
        sb.append("  - Attribute context: \" autofocus onfocus=alert(1) x=\".\n");
        sb.append("  - DOM XSS: look for sinks (innerHTML, document.write) and sources.\n");
        sb.append("  - Review CSP, HttpOnly, and output encoding behavior.\n\n");

        sb.append("RACE CONDITION\n");
        sb.append("  - Focus on non-atomic operations: balances, inventory, coupons.\n");
        sb.append("  - Send parallel requests; vary order and timing.\n");
        sb.append("  - Look for double-spend, duplicate submissions, or negative states.\n");
        sb.append("  - Identify missing locks, transactions, or unique constraints.\n");
        sb.append("  - Example: send 5 parallel /redeem requests for the same coupon.\n\n");

        sb.append("IDOR (INSECURE DIRECT OBJECT REFERENCE)\n");
        sb.append("  - Find object IDs in URLs, bodies, or JSON payloads.\n");
        sb.append("  - Swap IDs to another user or tenant; check read and write flows.\n");
        sb.append("  - Test predictable IDs (incremental, short UUIDs).\n");
        sb.append("  - Verify server-side checks, not just hidden UI.\n");
        sb.append("  - Example: /api/order/123 -> /api/order/124.\n\n");

        sb.append("BROKEN AUTHENTICATION\n");
        sb.append("  - Password reset tokens should expire and be single-use.\n");
        sb.append("  - Sessions must be invalidated on logout/reset/password change.\n");
        sb.append("  - Check for session fixation (session ID changes on login).\n");
        sb.append("  - Validate MFA enforcement on sensitive actions.\n");
        sb.append("  - Ensure rate limiting and lockout defenses.\n");
        sb.append("  - Example: reuse a password reset token.\n\n");

        sb.append("BROKEN ACCESS CONTROL (OWASP)\n");
        sb.append("  - Attempt forced browsing to privileged URLs/endpoints.\n");
        sb.append("  - Verify role-based checks on every request.\n");
        sb.append("  - Try method tampering (GET->POST) and parameter pollution.\n");
        sb.append("  - Test hidden admin flags (is_admin=true).\n");
        sb.append("  - Example: access /admin/users as a regular user.\n\n");

        sb.append("CRYPTOGRAPHIC FAILURES (OWASP)\n");
        sb.append("  - Confirm TLS settings, HSTS, and secure cookies.\n");
        sb.append("  - Check encryption for sensitive data at rest.\n");
        sb.append("  - Avoid weak hashes or improper key management.\n");
        sb.append("  - Example: JWT signed with weak secret.\n\n");

        sb.append("INSECURE DESIGN (OWASP)\n");
        sb.append("  - Look for missing abuse-case coverage and compensating controls.\n");
        sb.append("  - Validate trust boundaries and critical workflows.\n");
        sb.append("  - Example: refund without approval step.\n\n");

        sb.append("SECURITY MISCONFIGURATION (OWASP)\n");
        sb.append("  - Check default creds, verbose errors, and debug endpoints.\n");
        sb.append("  - Review CORS, directory listing, and stack traces.\n");
        sb.append("  - Example: /actuator/env exposed.\n\n");

        sb.append("VULNERABLE AND OUTDATED COMPONENTS (OWASP)\n");
        sb.append("  - Identify library versions and check for known CVEs.\n");
        sb.append("  - Flag EOL frameworks or unsupported dependencies.\n");
        sb.append("  - Example: jQuery 1.x with known CVE.\n\n");

        sb.append("IDENTIFICATION & AUTHENTICATION FAILURES (OWASP)\n");
        sb.append("  - Weak passwords, missing MFA, or no brute-force protections.\n");
        sb.append("  - Example: no MFA on email change.\n\n");

        sb.append("SOFTWARE & DATA INTEGRITY FAILURES (OWASP)\n");
        sb.append("  - Insecure deserialization or unsigned update pipelines.\n");
        sb.append("  - Dependency trust issues and CI/CD tampering risks.\n");
        sb.append("  - Example: unsigned update package download.\n\n");

        sb.append("SECURITY LOGGING & MONITORING FAILURES (OWASP)\n");
        sb.append("  - Missing audit trails for auth and privileged actions.\n");
        sb.append("  - Lack of alerts on suspicious activity.\n");
        sb.append("  - Example: failed logins not logged.\n\n");

        sb.append("SSRF (OWASP)\n");
        sb.append("  - Test URL fetchers: webhooks, importers, PDF generators.\n");
        sb.append("  - Try internal hosts and metadata 169.254.169.254.\n");
        sb.append("  - Bypass filters with redirects, DNS, or alternate schemes.\n\n");

        sb.append("CSRF\n");
        sb.append("  - State-changing endpoints should require CSRF tokens.\n");
        sb.append("  - Verify SameSite cookie flags and origin checks.\n");
        sb.append("  - Look for GET requests that change state.\n");
        sb.append("  - Example: auto-submit form from attacker site.\n\n");

        sb.append("COMMAND INJECTION\n");
        sb.append("  - Look for shell-outs in backup/export/diagnostics.\n");
        sb.append("  - Payload probes: ;id  |whoami  && uname -a\n");
        sb.append("  - Test command separators: ; & | || && $( ) ` `\n\n");

        sb.append("PATH TRAVERSAL\n");
        sb.append("  - Test file parameters: ../../etc/passwd or ..\\\\..\\\\windows\\\\win.ini\n");
        sb.append("  - Try URL encoding: %2e%2e%2f or double-encoding.\n");
        sb.append("  - Check read + write paths (download + upload).\n\n");

        sb.append("FILE UPLOAD\n");
        sb.append("  - Bypass extension filters: .php.jpg, .jsp;.jpg, .svg\n");
        sb.append("  - Check content-type validation vs magic bytes.\n");
        sb.append("  - Verify files are stored outside web root.\n\n");

        sb.append("XXE (XML EXTERNAL ENTITIES)\n");
        sb.append("  - Look for XML parsers: SOAP, SAML, SVG, Docx.\n");
        sb.append("  - Try inline DTD with &xxe; to read local files.\n");
        sb.append("  - Confirm external entity resolution is disabled.\n\n");

        sb.append("SSTI (SERVER-SIDE TEMPLATE INJECTION)\n");
        sb.append("  - Probe with {{7*7}}, ${7*7}, or <%= 7*7 %>.\n");
        sb.append("  - Look for reflected template rendering in emails/pages.\n\n");

        sb.append("OPEN REDIRECT\n");
        sb.append("  - Test next/return/url params: ?next=https://evil.com\n");
        sb.append("  - Check URL validation and allowlists.\n\n");

        sb.append("CORS MISCONFIGURATION\n");
        sb.append("  - Check Access-Control-Allow-Origin with credentials.\n");
        sb.append("  - Verify reflect-origin patterns and wildcard usage.\n\n");

        sb.append("JWT / TOKEN ISSUES\n");
        sb.append("  - Check for alg=none or weak HMAC secrets.\n");
        sb.append("  - Validate exp, aud, iss, and signature verification.\n\n");

        sb.append("OAUTH / SSO\n");
        sb.append("  - Test redirect_uri validation and open redirect chaining.\n");
        sb.append("  - Ensure state parameter is required and validated.\n\n");

        sb.append("CLICKJACKING\n");
        sb.append("  - Check X-Frame-Options and CSP frame-ancestors.\n");
        sb.append("  - Test sensitive pages inside an iframe.\n\n");

        sb.append("RATE LIMITING / BRUTE FORCE\n");
        sb.append("  - Attempt credential stuffing with slow ramp.\n");
        sb.append("  - Check lockout, CAPTCHA, and IP/device throttling.\n");
        sb.append("  - Example: 1000 login attempts without lockout.\n\n");

        sb.append("HOST HEADER INJECTION\n");
        sb.append("  - Test password reset links built from Host header.\n");
        sb.append("  - Look for cache poisoning or URL generation issues.\n\n");

        sb.append("DESERIALIZATION\n");
        sb.append("  - Identify serialized blobs (Java rO0AB, PHP O:).\n");
        sb.append("  - Check for type confusion or gadget chains.\n\n");

        return sb.toString();
    }

    private static Map<String, LanguageProfile> buildLanguageProfiles() {
        Map<String, LanguageProfile> profiles = new HashMap<>();

        profiles.put("python", new LanguageProfile(
            keywordSet("def", "class", "return", "if", "elif", "else", "for", "while", "break", "continue",
                "try", "except", "finally", "with", "as", "import", "from", "pass", "raise", "lambda",
                "yield", "global", "nonlocal", "assert", "True", "False", "None"),
            Arrays.asList("#"),
            null,
            null,
            false,
            false
        ));

        profiles.put("bash", new LanguageProfile(
            keywordSet("if", "then", "fi", "for", "in", "do", "done", "case", "esac", "while", "until", "function", "select", "time",
                "echo", "printf", "grep", "sed", "awk", "cat", "curl", "wget", "ls", "cd", "pwd", "chmod", "chown", "sudo", "export",
                "set", "unset", "trap", "true", "false"),
            Arrays.asList("#"),
            null,
            null,
            false,
            true
        ));

        profiles.put("go", new LanguageProfile(
            keywordSet("package", "import", "func", "return", "if", "else", "for", "range", "switch", "case", "default",
                "break", "continue", "go", "defer", "struct", "interface", "map", "chan", "var", "const", "type", "select", "nil", "true", "false"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("javascript", new LanguageProfile(
            keywordSet("function", "return", "if", "else", "for", "while", "switch", "case", "break", "continue",
                "const", "let", "var", "class", "new", "this", "try", "catch", "finally", "throw", "import", "from",
                "export", "default", "true", "false", "null", "undefined", "async", "await"),
            Arrays.asList("//"),
            "/*",
            "*/",
            true,
            false
        ));

        profiles.put("typescript", new LanguageProfile(
            keywordSet("function", "return", "if", "else", "for", "while", "switch", "case", "break", "continue",
                "const", "let", "var", "class", "new", "this", "try", "catch", "finally", "throw", "import", "from",
                "export", "default", "true", "false", "null", "undefined", "async", "await", "interface", "type", "enum"),
            Arrays.asList("//"),
            "/*",
            "*/",
            true,
            false
        ));

        profiles.put("java", new LanguageProfile(
            keywordSet("class", "interface", "public", "private", "protected", "static", "final", "void", "int", "long",
                "boolean", "if", "else", "for", "while", "switch", "case", "break", "continue", "return", "new", "try",
                "catch", "finally", "throw", "extends", "implements", "this", "super", "null", "true", "false"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("c", new LanguageProfile(
            keywordSet("int", "long", "char", "float", "double", "void", "struct", "typedef", "enum", "if", "else", "for",
                "while", "switch", "case", "break", "continue", "return", "static", "const", "sizeof", "null"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("cpp", new LanguageProfile(
            keywordSet("int", "long", "char", "float", "double", "void", "struct", "class", "namespace", "template",
                "if", "else", "for", "while", "switch", "case", "break", "continue", "return", "static", "const",
                "public", "private", "protected", "new", "delete", "nullptr"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("csharp", new LanguageProfile(
            keywordSet("class", "interface", "public", "private", "protected", "static", "void", "int", "string", "bool",
                "if", "else", "for", "while", "switch", "case", "break", "continue", "return", "new", "try", "catch",
                "finally", "throw", "null", "true", "false", "using", "namespace"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("php", new LanguageProfile(
            keywordSet("function", "return", "if", "else", "elseif", "for", "foreach", "while", "switch", "case",
                "break", "continue", "class", "public", "private", "protected", "static", "new", "try", "catch",
                "finally", "throw", "null", "true", "false"),
            Arrays.asList("//", "#"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("ruby", new LanguageProfile(
            keywordSet("def", "class", "module", "return", "if", "elsif", "else", "end", "for", "while", "do", "break",
                "next", "redo", "retry", "true", "false", "nil", "require"),
            Arrays.asList("#"),
            null,
            null,
            false,
            false
        ));

        profiles.put("rust", new LanguageProfile(
            keywordSet("fn", "let", "mut", "pub", "struct", "enum", "impl", "trait", "match", "if", "else", "for", "while",
                "loop", "break", "continue", "return", "true", "false", "None", "Some", "use", "mod"),
            Arrays.asList("//"),
            "/*",
            "*/",
            false,
            false
        ));

        profiles.put("sql", new LanguageProfile(
            keywordSet("select", "from", "where", "and", "or", "join", "left", "right", "inner", "outer", "group", "by",
                "order", "insert", "update", "delete", "into", "values", "create", "alter", "drop", "table", "view",
                "index", "limit", "offset", "distinct"),
            Arrays.asList("--"),
            "/*",
            "*/",
            false,
            true
        ));

        profiles.put("json", new LanguageProfile(
            keywordSet("true", "false", "null"),
            new ArrayList<>(),
            null,
            null,
            false,
            true
        ));

        profiles.put("yaml", new LanguageProfile(
            keywordSet("true", "false", "null", "yes", "no", "on", "off"),
            Arrays.asList("#"),
            null,
            null,
            false,
            true
        ));

        profiles.put("xml", new LanguageProfile(
            keywordSet(),
            new ArrayList<>(),
            null,
            null,
            false,
            false
        ));

        profiles.put("html", profiles.get("xml"));
        profiles.put("css", new LanguageProfile(
            keywordSet("color", "background", "display", "flex", "grid", "position", "absolute", "relative", "fixed",
                "margin", "padding", "border", "font", "font-size", "font-weight", "width", "height"),
            new ArrayList<>(),
            "/*",
            "*/",
            false,
            false
        ));

        return profiles;
    }

    private static Set<String> keywordSet(String... values) {
        Set<String> set = new HashSet<>();
        if (values == null) {
            return set;
        }
        for (String value : values) {
            if (value != null && !value.isEmpty()) {
                set.add(value.toLowerCase(Locale.ROOT));
            }
        }
        return set;
    }

    private static final class LanguageProfile {
        private final Set<String> keywords;
        private final List<String> lineComments;
        private final String blockStart;
        private final String blockEnd;
        private final boolean backtickStrings;
        private final boolean caseInsensitive;

        private LanguageProfile(Set<String> keywords, List<String> lineComments, String blockStart, String blockEnd, boolean backtickStrings, boolean caseInsensitive) {
            this.keywords = keywords == null ? new HashSet<>() : keywords;
            this.lineComments = lineComments == null ? new ArrayList<>() : lineComments;
            this.blockStart = blockStart;
            this.blockEnd = blockEnd;
            this.backtickStrings = backtickStrings;
            this.caseInsensitive = caseInsensitive;
        }
    }

    private final class TagChecklistCard extends JPanel {
        private final JPanel body;
        private final JButton toggleButton;
        private final JButton infoButton;
        private boolean collapsed;
        private final Map<String, JCheckBox> checkboxes = new LinkedHashMap<>();
        private final Runnable onChange;
        private final Runnable onInfo;
        private final Runnable onRemove;
        private final boolean isCustomCard;
        private final Consumer<String> onRemoveItem;
        private final Set<String> removableItems;
        private boolean updating;

        private TagChecklistCard(String tag,
                                 List<String> items,
                                 TagChecklistState state,
                                 Runnable onChange,
                                 Runnable onInfo,
                                 Runnable onRemove,
                                 boolean isCustomCard,
                                 Set<String> removableItems,
                                 Consumer<String> onRemoveItem) {
            super(new BorderLayout());
            this.onChange = onChange;
            this.onInfo = onInfo;
            this.onRemove = onRemove;
            this.isCustomCard = isCustomCard;
            this.onRemoveItem = onRemoveItem;
            this.removableItems = removableItems == null ? new HashSet<>() : removableItems;
            this.collapsed = state != null && state.collapsed;
            setBackground(surfaceBackground);
            setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(borderColor),
                BorderFactory.createEmptyBorder(6, 8, 6, 8)
            ));

            String displayTitle = truncateTitle(tag, 56);
            JLabel title = new JLabel(displayTitle);
            title.setFont(sectionFont);
            title.setForeground(accentColor);
            if (!displayTitle.equals(tag)) {
                title.setToolTipText(tag);
            } else {
                title.setToolTipText(null);
            }
            Dimension titleSize = title.getPreferredSize();
            title.setMinimumSize(new Dimension(0, titleSize.height));

            toggleButton = new JButton(collapsed ? "+" : "-");
            toggleButton.setFont(bodyFont);
            toggleButton.setMargin(new Insets(2, 6, 2, 6));
            toggleButton.addActionListener(event -> {
                setCollapsed(!collapsed);
                notifyChange();
            });

            infoButton = new JButton("i");
            infoButton.setFont(bodyFont);
            infoButton.setMargin(new Insets(2, 8, 2, 8));
            infoButton.setFocusPainted(false);
            infoButton.setForeground(accentColor);
            infoButton.setBackground(blend(surfaceBackground, borderColor, 0.08f));
            infoButton.setBorder(BorderFactory.createLineBorder(borderColor));
            infoButton.addActionListener(event -> notifyInfo());

            JPanel header = new JPanel(new BorderLayout());
            header.setBackground(surfaceBackground);
            JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 0));
            right.setBackground(surfaceBackground);
            right.add(infoButton);
            right.add(toggleButton);
            header.add(title, BorderLayout.CENTER);
            header.add(right, BorderLayout.EAST);

            body = new JPanel();
            body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
            body.setBackground(surfaceBackground);

            if (items != null) {
                for (String item : items) {
                    JCheckBox box = new JCheckBox(item);
                    box.setFont(bodyFont);
                    box.setBackground(surfaceBackground);
                    box.putClientProperty("itemText", item);
                    box.putClientProperty("normalColor", box.getForeground());
                    ChecklistItemState itemState = findItemState(state, item);
                    applyItemState(box, item, itemState);
                    box.addItemListener(event -> {
                        if (updating) {
                            return;
                        }
                        if (isNotApplicable(box)) {
                            updating = true;
                            box.setSelected(false);
                            updating = false;
                            return;
                        }
                        notifyChange();
                    });
                    body.add(box);
                    checkboxes.put(item, box);
                    attachChecklistItemPopup(box, item, isRemovableItem(item));
                }
            }

            body.setVisible(!collapsed);
            add(header, BorderLayout.NORTH);
            add(body, BorderLayout.CENTER);

            installChecklistPopup(this);
        }

        private void setCollapsed(boolean collapsed) {
            this.collapsed = collapsed;
            body.setVisible(!collapsed);
            toggleButton.setText(collapsed ? "+" : "-");
            revalidate();
            repaint();
        }

        private boolean isCollapsed() {
            return collapsed;
        }

        private ChecklistItemState findItemState(TagChecklistState state, String item) {
            if (state == null || item == null) {
                return null;
            }
            ChecklistItemState direct = state.itemStates.get(item);
            if (direct != null) {
                return direct;
            }
            for (Map.Entry<String, ChecklistItemState> entry : state.itemStates.entrySet()) {
                String key = entry.getKey();
                if (key != null && key.equalsIgnoreCase(item)) {
                    return entry.getValue();
                }
            }
            return null;
        }

        private void applyItemState(JCheckBox box, String item, ChecklistItemState state) {
            boolean isNa = state != null && state.notApplicable;
            boolean checked = state != null && state.checked && !isNa;
            updating = true;
            box.setSelected(checked);
            updating = false;
            setNotApplicable(box, item, isNa);
        }

        private boolean isNotApplicable(JCheckBox box) {
            return Boolean.TRUE.equals(box.getClientProperty("na"));
        }

        private void setNotApplicable(JCheckBox box, String item, boolean notApplicable) {
            box.putClientProperty("na", notApplicable);
            if (notApplicable) {
                updating = true;
                box.setSelected(false);
                updating = false;
                box.setText("----- " + item);
                box.setForeground(mutedText);
            } else {
                box.setText(item);
                Color normal = (Color) box.getClientProperty("normalColor");
                if (normal != null) {
                    box.setForeground(normal);
                }
            }
        }

        private void toggleNotApplicable(String item, JCheckBox box) {
            boolean isNa = isNotApplicable(box);
            setNotApplicable(box, item, !isNa);
            notifyChange();
        }

        private Map<String, ChecklistItemState> getItemStates() {
            Map<String, ChecklistItemState> states = new HashMap<>();
            for (Map.Entry<String, JCheckBox> entry : checkboxes.entrySet()) {
                JCheckBox box = entry.getValue();
                ChecklistItemState state = new ChecklistItemState();
                state.notApplicable = isNotApplicable(box);
                state.checked = box.isSelected() && !state.notApplicable;
                states.put(entry.getKey(), state);
            }
            return states;
        }

        private void notifyChange() {
            if (onChange != null) {
                onChange.run();
            }
        }

        private void notifyInfo() {
            if (onInfo != null) {
                onInfo.run();
            }
        }

        private void notifyRemove() {
            if (onRemove != null) {
                onRemove.run();
            }
        }

        private void notifyRemoveItem(String item) {
            if (onRemoveItem != null && item != null) {
                onRemoveItem.accept(item);
            }
        }

        private boolean isRemovableItem(String item) {
            if (item == null || removableItems == null || removableItems.isEmpty()) {
                return false;
            }
            return removableItems.contains(item.toLowerCase(Locale.ROOT));
        }

        private void attachChecklistItemPopup(JCheckBox box, String item, boolean removable) {
            box.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                private void maybeShow(java.awt.event.MouseEvent e) {
                    if (!e.isPopupTrigger()) {
                        return;
                    }
                    JPopupMenu menu = new JPopupMenu();
                    boolean isNa = isNotApplicable(box);
                    JMenuItem naItem = new JMenuItem(isNa ? "Clear N/A" : "Mark as N/A");
                    naItem.addActionListener(event -> toggleNotApplicable(item, box));
                    menu.add(naItem);
                    if (removable) {
                        JMenuItem removeItem = new JMenuItem("Remove item");
                        removeItem.addActionListener(event -> notifyRemoveItem(item));
                        menu.add(removeItem);
                    }
                    menu.show(e.getComponent(), e.getX(), e.getY());
                }
            });
        }

        private void installChecklistPopup(JComponent component) {
            JPopupMenu menu = new JPopupMenu();
            JMenuItem infoItem = new JMenuItem("Info");
            infoItem.addActionListener(event -> notifyInfo());
            String removeLabel = isCustomCard ? "Remove checklist" : "Unselect tag checklist";
            JMenuItem removeItem = new JMenuItem(removeLabel);
            removeItem.addActionListener(event -> notifyRemove());
            menu.add(infoItem);
            menu.add(removeItem);

            attachPopupExcludeCheckbox(component, menu);
        }

        private void attachPopupExcludeCheckbox(Component component, JPopupMenu menu) {
            if (component instanceof JCheckBox) {
                return;
            }
            component.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                private void maybeShow(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        menu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });
            if (component instanceof Container) {
                for (Component child : ((Container) component).getComponents()) {
                    attachPopupExcludeCheckbox(child, menu);
                }
            }
        }

        private void attachPopup(Component component, JPopupMenu menu) {
            component.addMouseListener(new java.awt.event.MouseAdapter() {
                @Override
                public void mousePressed(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                @Override
                public void mouseReleased(java.awt.event.MouseEvent e) {
                    maybeShow(e);
                }

                private void maybeShow(java.awt.event.MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        menu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });
        }
    }

    private TargetState getOrCreateState(String target) {
        return targetStates.computeIfAbsent(target, key -> new TargetState());
    }

    private static final class TargetState {
        private String notesText = "";
        private boolean autoSave;
        private final Set<String> selectedTags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        private final List<String> attachments = new ArrayList<>();
        private final Map<String, String> attachmentHashes = new HashMap<>();
        private final Map<String, TagChecklistState> checklistStates = new HashMap<>();
        private final Map<String, List<String>> customChecklistItems = new LinkedHashMap<>();
        private final Map<String, CustomChecklist> customChecklists = new LinkedHashMap<>();
        private boolean loaded;
        private boolean dirty;
    }

    private static final class ChecklistItemState {
        private boolean checked;
        private boolean notApplicable;

        private ChecklistItemState() {
        }

        private ChecklistItemState(boolean checked, boolean notApplicable) {
            this.checked = checked;
            this.notApplicable = notApplicable;
        }
    }

    private static final class TagChecklistState {
        private final Map<String, ChecklistItemState> itemStates = new HashMap<>();
        private boolean collapsed;
    }

    private static final class TargetStateSnapshot {
        private final String target;
        private final String notesText;
        private final boolean autoSave;
        private final Set<String> selectedTags;
        private final List<String> attachments;
        private final Map<String, TagChecklistState> checklistStates;
        private final Map<String, List<String>> customChecklistItems;
        private final Map<String, CustomChecklist> customChecklists;

        private TargetStateSnapshot(String target,
                                    String notesText,
                                    boolean autoSave,
                                    Set<String> selectedTags,
                                    List<String> attachments,
                                    Map<String, TagChecklistState> checklistStates,
                                    Map<String, List<String>> customChecklistItems,
                                    Map<String, CustomChecklist> customChecklists) {
            this.target = target;
            this.notesText = notesText;
            this.autoSave = autoSave;
            this.selectedTags = selectedTags;
            this.attachments = attachments;
            this.checklistStates = checklistStates;
            this.customChecklistItems = customChecklistItems;
            this.customChecklists = customChecklists;
        }

        private static TargetStateSnapshot from(String target, TargetState state) {
            Set<String> tags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
            tags.addAll(state.selectedTags);

            List<String> attachments = new ArrayList<>(state.attachments);

            Map<String, TagChecklistState> checklistStates = new HashMap<>();
            for (Map.Entry<String, TagChecklistState> entry : state.checklistStates.entrySet()) {
                TagChecklistState original = entry.getValue();
                if (original == null) {
                    continue;
                }
                TagChecklistState copy = new TagChecklistState();
                copy.collapsed = original.collapsed;
                for (Map.Entry<String, ChecklistItemState> itemEntry : original.itemStates.entrySet()) {
                    ChecklistItemState originalItem = itemEntry.getValue();
                    ChecklistItemState itemCopy = new ChecklistItemState();
                    if (originalItem != null) {
                        itemCopy.checked = originalItem.checked;
                        itemCopy.notApplicable = originalItem.notApplicable;
                    }
                    copy.itemStates.put(itemEntry.getKey(), itemCopy);
                }
                checklistStates.put(entry.getKey(), copy);
            }

            Map<String, List<String>> customChecklistItems = new LinkedHashMap<>();
            for (Map.Entry<String, List<String>> entry : state.customChecklistItems.entrySet()) {
                if (entry.getKey() == null || entry.getValue() == null) {
                    continue;
                }
                customChecklistItems.put(entry.getKey(), new ArrayList<>(entry.getValue()));
            }

            Map<String, CustomChecklist> customChecklists = new LinkedHashMap<>();
            for (Map.Entry<String, CustomChecklist> entry : state.customChecklists.entrySet()) {
                CustomChecklist checklist = entry.getValue();
                if (checklist == null) {
                    continue;
                }
                CustomChecklist copy = new CustomChecklist(checklist.id, checklist.title, checklist.afterKey, checklist.items);
                customChecklists.put(entry.getKey(), copy);
            }

            return new TargetStateSnapshot(target,
                state.notesText,
                state.autoSave,
                tags,
                attachments,
                checklistStates,
                customChecklistItems,
                customChecklists
            );
        }
    }

    private static final class CustomChecklist {
        private final String id;
        private final String title;
        private final String afterKey;
        private final List<String> items;

        private CustomChecklist(String id, String title, String afterKey, List<String> items) {
            this.id = id;
            this.title = title;
            this.afterKey = afterKey == null ? "" : afterKey;
            this.items = items == null ? new ArrayList<>() : new ArrayList<>(items);
        }
    }

    private static final class TargetExport {
        private final String target;
        private final String notes;

        private TargetExport(String target, String notes) {
            this.target = target;
            this.notes = notes;
        }
    }

    private static final class TableRender {
        private final String html;
        private final int nextIndex;

        private TableRender(String html, int nextIndex) {
            this.html = html == null ? "" : html;
            this.nextIndex = nextIndex;
        }
    }

    private static final class ImportedTarget {
        private final String target;
        private String notes;

        private ImportedTarget(String target, String notes) {
            this.target = target;
            this.notes = notes == null ? "" : notes;
        }
    }

    private static final class SimpleJsonParser {
        private final String input;
        private int index;

        private SimpleJsonParser(String input) {
            this.input = input == null ? "" : input;
        }

        private Object parse() {
            skipWhitespace();
            Object value = parseValue();
            skipWhitespace();
            if (index < input.length()) {
                throw new IllegalArgumentException("Unexpected trailing data at position " + index);
            }
            return value;
        }

        private Object parseValue() {
            skipWhitespace();
            if (index >= input.length()) {
                throw new IllegalArgumentException("Unexpected end of JSON");
            }
            char c = input.charAt(index);
            if (c == '{') {
                return parseObject();
            }
            if (c == '[') {
                return parseArray();
            }
            if (c == '\"') {
                return parseString();
            }
            if (c == 't') {
                consumeLiteral("true");
                return Boolean.TRUE;
            }
            if (c == 'f') {
                consumeLiteral("false");
                return Boolean.FALSE;
            }
            if (c == 'n') {
                consumeLiteral("null");
                return null;
            }
            if (c == '-' || Character.isDigit(c)) {
                return parseNumber();
            }
            throw new IllegalArgumentException("Unexpected character '" + c + "' at position " + index);
        }

        private Map<String, Object> parseObject() {
            Map<String, Object> map = new LinkedHashMap<>();
            expect('{');
            skipWhitespace();
            if (peek('}')) {
                index++;
                return map;
            }
            while (true) {
                skipWhitespace();
                String key = parseString();
                skipWhitespace();
                expect(':');
                Object value = parseValue();
                map.put(key, value);
                skipWhitespace();
                if (peek('}')) {
                    index++;
                    break;
                }
                expect(',');
            }
            return map;
        }

        private List<Object> parseArray() {
            List<Object> list = new ArrayList<>();
            expect('[');
            skipWhitespace();
            if (peek(']')) {
                index++;
                return list;
            }
            while (true) {
                Object value = parseValue();
                list.add(value);
                skipWhitespace();
                if (peek(']')) {
                    index++;
                    break;
                }
                expect(',');
            }
            return list;
        }

        private String parseString() {
            expect('\"');
            StringBuilder sb = new StringBuilder();
            while (index < input.length()) {
                char c = input.charAt(index++);
                if (c == '\"') {
                    break;
                }
                if (c == '\\') {
                    if (index >= input.length()) {
                        throw new IllegalArgumentException("Invalid escape at end of string");
                    }
                    char esc = input.charAt(index++);
                    switch (esc) {
                        case '\"':
                            sb.append('\"');
                            break;
                        case '\\':
                            sb.append('\\');
                            break;
                        case '/':
                            sb.append('/');
                            break;
                        case 'b':
                            sb.append('\b');
                            break;
                        case 'f':
                            sb.append('\f');
                            break;
                        case 'n':
                            sb.append('\n');
                            break;
                        case 'r':
                            sb.append('\r');
                            break;
                        case 't':
                            sb.append('\t');
                            break;
                        case 'u':
                            sb.append(parseUnicode());
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid escape \\" + esc + " at position " + index);
                    }
                } else {
                    sb.append(c);
                }
            }
            return sb.toString();
        }

        private char parseUnicode() {
            if (index + 4 > input.length()) {
                throw new IllegalArgumentException("Invalid unicode escape");
            }
            int code = 0;
            for (int i = 0; i < 4; i++) {
                char c = input.charAt(index++);
                int value;
                if (c >= '0' && c <= '9') {
                    value = c - '0';
                } else if (c >= 'a' && c <= 'f') {
                    value = 10 + (c - 'a');
                } else if (c >= 'A' && c <= 'F') {
                    value = 10 + (c - 'A');
                } else {
                    throw new IllegalArgumentException("Invalid unicode escape at position " + index);
                }
                code = (code << 4) + value;
            }
            return (char) code;
        }

        private Number parseNumber() {
            int start = index;
            if (peek('-')) {
                index++;
            }
            while (index < input.length() && Character.isDigit(input.charAt(index))) {
                index++;
            }
            if (peek('.')) {
                index++;
                while (index < input.length() && Character.isDigit(input.charAt(index))) {
                    index++;
                }
            }
            if (peek('e') || peek('E')) {
                index++;
                if (peek('+') || peek('-')) {
                    index++;
                }
                while (index < input.length() && Character.isDigit(input.charAt(index))) {
                    index++;
                }
            }
            String raw = input.substring(start, index);
            try {
                if (raw.contains(".") || raw.contains("e") || raw.contains("E")) {
                    return Double.parseDouble(raw);
                }
                return Long.parseLong(raw);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid number at position " + start);
            }
        }

        private void skipWhitespace() {
            while (index < input.length() && Character.isWhitespace(input.charAt(index))) {
                index++;
            }
        }

        private void consumeLiteral(String literal) {
            if (input.startsWith(literal, index)) {
                index += literal.length();
                return;
            }
            throw new IllegalArgumentException("Expected " + literal + " at position " + index);
        }

        private void expect(char expected) {
            if (index >= input.length() || input.charAt(index) != expected) {
                throw new IllegalArgumentException("Expected '" + expected + "' at position " + index);
            }
            index++;
        }

        private boolean peek(char c) {
            return index < input.length() && input.charAt(index) == c;
        }
    }

    private static final class SearchResult {
        private final String target;
        private final int lineNumber;
        private final String lineText;

        private SearchResult(String target, int lineNumber, String lineText) {
            this.target = target;
            this.lineNumber = lineNumber;
            this.lineText = lineText == null ? "" : lineText.trim();
        }

        @Override
        public String toString() {
            String snippet = lineText;
            if (snippet == null || snippet.isEmpty()) {
                snippet = "(blank)";
            }
            if (snippet.length() > 80) {
                snippet = snippet.substring(0, 77) + "...";
            }
            return target + " : line " + lineNumber + " — " + snippet;
        }
    }

    private static final class OutlineEntry {
        private final int level;
        private final String title;
        private final int lineNumber;

        private OutlineEntry(int level, String title, int lineNumber) {
            this.level = level;
            this.title = title == null ? "" : title;
            this.lineNumber = lineNumber;
        }

        @Override
        public String toString() {
            return title;
        }
    }

    private final class OutlineCellRenderer extends DefaultListCellRenderer {
        @Override
        public Component getListCellRendererComponent(JList<?> list,
                                                      Object value,
                                                      int index,
                                                      boolean isSelected,
                                                      boolean cellHasFocus) {
            Component component = super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
            if (component instanceof JLabel && value instanceof OutlineEntry) {
                OutlineEntry entry = (OutlineEntry) value;
                JLabel label = (JLabel) component;
                label.setFont(bodyFont);
                String prefix = "H" + entry.level + " ";
                label.setText(prefix + entry.title);
                int indent = Math.max(0, entry.level - 1) * 10;
                label.setBorder(BorderFactory.createEmptyBorder(2, 8 + indent, 2, 8));
                label.setToolTipText("Line " + entry.lineNumber);
            }
            return component;
        }
    }

    private static final class NotesViewState {
        private final JTextArea notesArea;
        private final UndoManager notesUndoManager;
        private final JEditorPane markdownPreview;
        private final JTabbedPane notesEditorTabs;
        private final JLabel notesTargetLabel;
        private final DefaultListModel<String> tagListModel;
        private final JList<String> tagList;
        private final JTextField newTagField;
        private final JButton addTagButton;
        private final JPanel tagChecklistContainer;
        private final JScrollPane tagChecklistScroll;
        private final JTextField addChecklistItemField;
        private final JButton addChecklistButton;
        private final DefaultListModel<String> attachmentListModel;
        private final JList<String> attachmentList;
        private final JButton pasteScreenshotButton;
        private final JButton removeAttachmentButton;
        private final JButton renameAttachmentButton;
        private final JButton detachNotesButton;
        private final JSplitPane notesEditorSplit;
        private final JPanel outlinePanel;
        private final JPanel outlinePlaceholder;
        private final DefaultListModel<OutlineEntry> outlineListModel;
        private final JList<OutlineEntry> outlineList;

        private NotesViewState(JTextArea notesArea,
                               UndoManager notesUndoManager,
                               JEditorPane markdownPreview,
                               JTabbedPane notesEditorTabs,
                               JLabel notesTargetLabel,
                               DefaultListModel<String> tagListModel,
                               JList<String> tagList,
                               JTextField newTagField,
                               JButton addTagButton,
                               JPanel tagChecklistContainer,
                               JScrollPane tagChecklistScroll,
                               JTextField addChecklistItemField,
                               JButton addChecklistButton,
                               DefaultListModel<String> attachmentListModel,
                               JList<String> attachmentList,
                               JButton pasteScreenshotButton,
                               JButton removeAttachmentButton,
                               JButton renameAttachmentButton,
                               JButton detachNotesButton,
                               JSplitPane notesEditorSplit,
                               JPanel outlinePanel,
                               JPanel outlinePlaceholder,
                               DefaultListModel<OutlineEntry> outlineListModel,
                               JList<OutlineEntry> outlineList) {
            this.notesArea = notesArea;
            this.notesUndoManager = notesUndoManager;
            this.markdownPreview = markdownPreview;
            this.notesEditorTabs = notesEditorTabs;
            this.notesTargetLabel = notesTargetLabel;
            this.tagListModel = tagListModel;
            this.tagList = tagList;
            this.newTagField = newTagField;
            this.addTagButton = addTagButton;
            this.tagChecklistContainer = tagChecklistContainer;
            this.tagChecklistScroll = tagChecklistScroll;
            this.addChecklistItemField = addChecklistItemField;
            this.addChecklistButton = addChecklistButton;
            this.attachmentListModel = attachmentListModel;
            this.attachmentList = attachmentList;
            this.pasteScreenshotButton = pasteScreenshotButton;
            this.removeAttachmentButton = removeAttachmentButton;
            this.renameAttachmentButton = renameAttachmentButton;
            this.detachNotesButton = detachNotesButton;
            this.notesEditorSplit = notesEditorSplit;
            this.outlinePanel = outlinePanel;
            this.outlinePlaceholder = outlinePlaceholder;
            this.outlineListModel = outlineListModel;
            this.outlineList = outlineList;
        }
    }

    private static final class SimpleDocumentListener implements DocumentListener {
        private final Runnable onChange;

        private SimpleDocumentListener(Runnable onChange) {
            this.onChange = onChange;
        }

        @Override
        public void insertUpdate(DocumentEvent event) {
            onChange.run();
        }

        @Override
        public void removeUpdate(DocumentEvent event) {
            onChange.run();
        }

        @Override
        public void changedUpdate(DocumentEvent event) {
            onChange.run();
        }
    }

    private static final class PublicSuffixList {
        private final Set<String> exactRules;
        private final Set<String> wildcardRules;
        private final Set<String> exceptionRules;
        private final boolean loaded;

        private PublicSuffixList(Set<String> exactRules, Set<String> wildcardRules, Set<String> exceptionRules, boolean loaded) {
            this.exactRules = exactRules;
            this.wildcardRules = wildcardRules;
            this.exceptionRules = exceptionRules;
            this.loaded = loaded;
        }

        private static PublicSuffixList load() {
            Path listPath = locatePublicSuffixList();
            if (listPath == null) {
                return new PublicSuffixList(new HashSet<>(), new HashSet<>(), new HashSet<>(), false);
            }

            Set<String> exact = new HashSet<>();
            Set<String> wildcard = new HashSet<>();
            Set<String> exception = new HashSet<>();

            try (BufferedReader reader = Files.newBufferedReader(listPath, StandardCharsets.UTF_8)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("//")) {
                        continue;
                    }
                    String normalized = line.toLowerCase(Locale.ROOT);
                    if (normalized.startsWith("!")) {
                        exception.add(normalized.substring(1));
                    } else if (normalized.startsWith("*.")) {
                        wildcard.add(normalized.substring(2));
                    } else {
                        exact.add(normalized);
                    }
                }
            } catch (IOException e) {
                return new PublicSuffixList(new HashSet<>(), new HashSet<>(), new HashSet<>(), false);
            }

            return new PublicSuffixList(exact, wildcard, exception, true);
        }

        private static Path locatePublicSuffixList() {
            String javaHome = System.getProperty("java.home");
            if (javaHome != null && !javaHome.isEmpty()) {
                Path direct = Paths.get(javaHome, "lib", "security", "public_suffix_list.dat");
                if (Files.exists(direct)) {
                    return direct;
                }
                Path legacy = Paths.get(javaHome, "jre", "lib", "security", "public_suffix_list.dat");
                if (Files.exists(legacy)) {
                    return legacy;
                }
            }
            return null;
        }

        private boolean isLoaded() {
            return loaded;
        }

        private String getRegistrableDomain(String host) {
            String cleaned = host == null ? null : host.toLowerCase(Locale.ROOT);
            if (cleaned == null || cleaned.isEmpty()) {
                return null;
            }
            String publicSuffix = getPublicSuffix(cleaned);
            if (publicSuffix == null) {
                return null;
            }
            if (publicSuffix.equals(cleaned)) {
                return cleaned;
            }

            String[] hostParts = cleaned.split("\\.");
            String[] suffixParts = publicSuffix.split("\\.");
            if (hostParts.length <= suffixParts.length) {
                return cleaned;
            }
            int start = hostParts.length - suffixParts.length - 1;
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < hostParts.length; i++) {
                if (sb.length() > 0) {
                    sb.append('.');
                }
                sb.append(hostParts[i]);
            }
            return sb.toString();
        }

        private String getPublicSuffix(String host) {
            String[] parts = host.split("\\.");
            String exceptionMatch = null;
            String exactMatch = null;
            String wildcardMatch = null;

            for (int i = 0; i < parts.length; i++) {
                String candidate = join(parts, i);
                if (exceptionRules.contains(candidate)) {
                    exceptionMatch = candidate;
                    break;
                }
                if (exactMatch == null && exactRules.contains(candidate)) {
                    exactMatch = candidate;
                }
                if (wildcardMatch == null && i + 1 < parts.length) {
                    String wildcardCandidate = join(parts, i + 1);
                    if (wildcardRules.contains(wildcardCandidate)) {
                        wildcardMatch = candidate;
                    }
                }
            }

            if (exceptionMatch != null) {
                String[] excParts = exceptionMatch.split("\\.");
                if (excParts.length <= 1) {
                    return exceptionMatch;
                }
                return join(excParts, 1);
            }

            String rule = null;
            if (exactMatch != null && wildcardMatch != null) {
                int exactLabels = countLabels(exactMatch);
                int wildcardLabels = countLabels(wildcardMatch);
                rule = exactLabels >= wildcardLabels ? exactMatch : wildcardMatch;
            } else if (exactMatch != null) {
                rule = exactMatch;
            } else if (wildcardMatch != null) {
                rule = wildcardMatch;
            }

            if (rule == null) {
                return parts[parts.length - 1];
            }
            return rule;
        }

        private int countLabels(String value) {
            if (value == null || value.isEmpty()) {
                return 0;
            }
            int count = 1;
            for (int i = 0; i < value.length(); i++) {
                if (value.charAt(i) == '.') {
                    count++;
                }
            }
            return count;
        }

        private String join(String[] parts, int start) {
            StringBuilder sb = new StringBuilder();
            for (int i = start; i < parts.length; i++) {
                if (sb.length() > 0) {
                    sb.append('.');
                }
                sb.append(parts[i]);
            }
            return sb.toString();
        }
    }
}
