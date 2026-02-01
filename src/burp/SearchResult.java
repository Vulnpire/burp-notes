package burp;

final class SearchResult {
    final String target;
    final int lineNumber;
    final String lineText;

    SearchResult(String target, int lineNumber, String lineText) {
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
