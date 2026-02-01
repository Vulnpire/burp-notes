package burp;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class SimpleJsonParser {
    private final String input;
    private int index;

    SimpleJsonParser(String input) {
        this.input = input == null ? "" : input;
    }

    Object parse() {
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
        expect('{');
        Map<String, Object> map = new HashMap<>();
        skipWhitespace();
        if (peek('}')) {
            index++;
            return map;
        }
        while (index < input.length()) {
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
        expect('[');
        List<Object> list = new ArrayList<>();
        skipWhitespace();
        if (peek(']')) {
            index++;
            return list;
        }
        while (index < input.length()) {
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
                    break;
                }
                char next = input.charAt(index++);
                switch (next) {
                    case '\"':
                    case '\\':
                    case '/':
                        sb.append(next);
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
                        if (index + 4 <= input.length()) {
                            String hex = input.substring(index, index + 4);
                            index += 4;
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException ignored) {
                                sb.append("\\u").append(hex);
                            }
                        }
                        break;
                    default:
                        sb.append(next);
                        break;
                }
                continue;
            }
            sb.append(c);
        }
        return sb.toString();
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
        String value = input.substring(start, index);
        try {
            if (value.contains(".") || value.contains("e") || value.contains("E")) {
                return Double.parseDouble(value);
            }
            long parsed = Long.parseLong(value);
            if (parsed >= Integer.MIN_VALUE && parsed <= Integer.MAX_VALUE) {
                return (int) parsed;
            }
            return parsed;
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private void skipWhitespace() {
        while (index < input.length()) {
            char c = input.charAt(index);
            if (Character.isWhitespace(c)) {
                index++;
            } else {
                break;
            }
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
