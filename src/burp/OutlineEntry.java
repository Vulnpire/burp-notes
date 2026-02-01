package burp;

final class OutlineEntry {
    final int level;
    final String title;
    final int lineNumber;

    OutlineEntry(int level, String title, int lineNumber) {
        this.level = level;
        this.title = title == null ? "" : title;
        this.lineNumber = lineNumber;
    }

    @Override
    public String toString() {
        return title;
    }
}
