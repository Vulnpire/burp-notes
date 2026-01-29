package burp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class TagDefinition {
    private final String name;
    private final TagCategory category;
    private final List<String> checklist;
    private final List<String> testIdeas;
    private final boolean includeTable;

    TagDefinition(String name, TagCategory category, List<String> checklist, List<String> testIdeas, boolean includeTable) {
        this.name = name;
        this.category = category == null ? TagCategory.GENERAL : category;
        this.checklist = checklist == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(checklist));
        this.testIdeas = testIdeas == null ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(testIdeas));
        this.includeTable = includeTable;
    }

    String getName() {
        return name;
    }

    TagCategory getCategory() {
        return category;
    }

    List<String> getChecklist() {
        return checklist;
    }

    List<String> getTestIdeas() {
        return testIdeas;
    }

    boolean isIncludeTable() {
        return includeTable;
    }
}
