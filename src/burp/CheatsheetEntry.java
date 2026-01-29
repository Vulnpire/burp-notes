package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class CheatsheetEntry {
    private final String title;
    private final List<String> bullets;
    private final String identify;
    private final String recon;
    private final String exploit;

    CheatsheetEntry(String title, List<String> bullets, String identify, String recon, String exploit) {
        this.title = title == null ? "" : title;
        this.bullets = bullets == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(bullets));
        this.identify = identify == null ? "" : identify;
        this.recon = recon == null ? "" : recon;
        this.exploit = exploit == null ? "" : exploit;
    }

    CheatsheetEntry(String title, List<String> bullets, String recon, String exploit) {
        this(title, bullets, "", recon, exploit);
    }

    String getTitle() {
        return title;
    }

    List<String> getBullets() {
        return bullets;
    }

    String getIdentify() {
        return identify;
    }

    String getRecon() {
        return recon;
    }

    String getExploit() {
        return exploit;
    }
}
