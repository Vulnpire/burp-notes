package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.Locale;

final class TargetState {
    String notesText = "";
    boolean autoSave;
    final Set<String> selectedTags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    final Set<String> notApplicableTags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
    final List<String> attachments = new ArrayList<>();
    final Map<String, String> attachmentHashes = new HashMap<>();
    final Map<String, TagChecklistState> checklistStates = new HashMap<>();
    final Map<String, List<String>> customChecklistItems = new LinkedHashMap<>();
    final Map<String, CustomChecklist> customChecklists = new LinkedHashMap<>();
    boolean loaded;
    boolean dirty;
}

final class ChecklistItemState {
    boolean checked;
    boolean notApplicable;

    ChecklistItemState() {
    }

    ChecklistItemState(boolean checked, boolean notApplicable) {
        this.checked = checked;
        this.notApplicable = notApplicable;
    }
}

final class TagChecklistState {
    final Map<String, ChecklistItemState> itemStates = new HashMap<>();
    boolean collapsed;
}

final class TargetStateSnapshot {
    final String target;
    final String notesText;
    final boolean autoSave;
    final Set<String> selectedTags;
    final Set<String> notApplicableTags;
    final List<String> attachments;
    final Map<String, TagChecklistState> checklistStates;
    final Map<String, List<String>> customChecklistItems;
    final Map<String, CustomChecklist> customChecklists;

    TargetStateSnapshot(String target,
                        String notesText,
                        boolean autoSave,
                        Set<String> selectedTags,
                        Set<String> notApplicableTags,
                        List<String> attachments,
                        Map<String, TagChecklistState> checklistStates,
                        Map<String, List<String>> customChecklistItems,
                        Map<String, CustomChecklist> customChecklists) {
        this.target = target;
        this.notesText = notesText;
        this.autoSave = autoSave;
        this.selectedTags = selectedTags;
        this.notApplicableTags = notApplicableTags;
        this.attachments = attachments;
        this.checklistStates = checklistStates;
        this.customChecklistItems = customChecklistItems;
        this.customChecklists = customChecklists;
    }

    static TargetStateSnapshot from(String target, TargetState state) {
        Set<String> tags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        tags.addAll(state.selectedTags);
        Set<String> naTags = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        naTags.addAll(state.notApplicableTags);

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
            naTags,
            attachments,
            checklistStates,
            customChecklistItems,
            customChecklists
        );
    }
}

final class CustomChecklist {
    final String id;
    final String title;
    final String afterKey;
    final List<String> items;

    CustomChecklist(String id, String title, String afterKey, List<String> items) {
        this.id = id;
        this.title = title;
        this.afterKey = afterKey == null ? "" : afterKey;
        this.items = items == null ? new ArrayList<>() : new ArrayList<>(items);
    }
}

final class TargetExport {
    final String target;
    final String notes;

    TargetExport(String target, String notes) {
        this.target = target;
        this.notes = notes;
    }
}

final class TableRender {
    final String html;
    final int nextIndex;

    TableRender(String html, int nextIndex) {
        this.html = html == null ? "" : html;
        this.nextIndex = nextIndex;
    }
}

final class ImportedTarget {
    final String target;
    String notes;

    ImportedTarget(String target, String notes) {
        this.target = target;
        this.notes = notes == null ? "" : notes;
    }
}
