package burp;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

final class LanguageProfile {
    final Set<String> keywords;
    final List<String> lineComments;
    final String blockStart;
    final String blockEnd;
    final boolean backtickStrings;
    final boolean caseInsensitive;

    LanguageProfile(Set<String> keywords, List<String> lineComments, String blockStart, String blockEnd, boolean backtickStrings, boolean caseInsensitive) {
        this.keywords = keywords == null ? new HashSet<>() : keywords;
        this.lineComments = lineComments == null ? new ArrayList<>() : lineComments;
        this.blockStart = blockStart;
        this.blockEnd = blockEnd;
        this.backtickStrings = backtickStrings;
        this.caseInsensitive = caseInsensitive;
    }
}
