import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

public class PasswordCrack {

    private static class UserEntry {
        String _username;
        String _salt;
        String _encryptedPassword;
        boolean _isCracked = false;

        UserEntry(String line) {
            String[] parts = line.split(":", 3); // account:hash:rest
            _username = parts[0];
            // Password field is parts[1]. Salt is first 2 chars of parts[1].
            _salt = parts[1].substring(0, 2);
            _encryptedPassword = parts[1];
        }
    }

    private static final char[] MangleChars;
    static {
        List<Character> chars = new ArrayList<>();
        for (char c = 'a'; c <= 'z'; c++) {
            chars.add(c);
        }
        for (char c = 'A'; c <= 'Z'; c++) {
            chars.add(c);
        }
        for (char c = '0'; c <= '9'; c++) {
            chars.add(c);
        }
        MangleChars = new char[chars.size()];
        for (int i = 0; i < chars.size(); i++) {
            MangleChars[i] = chars.get(i);
        }
    }

    public static void Main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java PasswordCrack <dictionary_file> <password_file>");
            System.exit(1);
        }

        String dictionaryFile = args[0];
        String passwordFile = args[1];

        if (!Files.isReadable(Paths.get(dictionaryFile))) {
            System.err.println("Error: Dictionary file '" + dictionaryFile + "' not found or not readable.");
            System.exit(1);
        }
        if (!Files.isReadable(Paths.get(passwordFile))) {
            System.err.println("Error: Password file '" + passwordFile + "' not found or not readable.");
            System.exit(1);
        }

        List<String> dictionary = LoadDictionary(dictionaryFile);
        List<UserEntry> users = LoadPasswordEntries(passwordFile);

        if (dictionary == null || users == null) {
            System.exit(1);
        }
        if (dictionary.isEmpty() && users.isEmpty()) {
            System.err.println("Error: Both dictionary and password file are effectively empty or failed to load.");
            System.exit(1);
        }
        if (users.isEmpty()) {
            System.err.println("Error: No user entries loaded from password file.");
            System.exit(1);
        }

        AtomicInteger crackedCount = new AtomicInteger(0);
        int totalUsers = users.size();

        // New Stage 1: Try usernames directly
        TryUsernamesAsPasswords(users, crackedCount, totalUsers);
        if (crackedCount.get() == totalUsers) {
            return;
        }

        // New Stage 2: Try mangled usernames
        TryMangledUsernames(users, crackedCount, totalUsers);
        if (crackedCount.get() == totalUsers) {
            return;
        }

        if (dictionary.isEmpty()) {
            // Potentially exit or just note that remaining users couldn't be cracked if
            // dictionary is required from here
            if (crackedCount.get() < totalUsers) {
                System.out.println(crackedCount.get() + " out of " + totalUsers
                        + " passwords cracked. Remaining could not be attempted without a dictionary.");
            }
            return;
        }

        // Stage 3: Level 0 Dictionary (No Mangles)
        TryWordCombinations(dictionary, users, crackedCount, totalUsers, 0);
        if (crackedCount.get() == totalUsers) {
            return;
        }

        // Stage 4: Level 1 Dictionary (One Mangle)
        TryWordCombinations(dictionary, users, crackedCount, totalUsers, 1);
        if (crackedCount.get() == totalUsers) {
            return;
        }

        // Stage 5: Level 2 Dictionary (Two Mangles)
        TryWordCombinations(dictionary, users, crackedCount, totalUsers, 2);

    }

    private static List<String> LoadDictionary(String filePath) {
        try {
            return Files.readAllLines(Paths.get(filePath));
        } catch (IOException err) {
            System.err.println("Error reading dictionary file: " + err.getMessage());
            return null;
        }
    }

    private static List<UserEntry> LoadPasswordEntries(String filePath) {
        List<UserEntry> entries = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) {
                    continue;
                }

                String[] parts = line.split(":");
                // A valid line needs at least user:pass_field
                // pass_field must be at least 2 chars for salt
                if (parts.length < 2 || parts[1].length() < 2) {
                    System.err.println("Warning: Skipping malformed line in password file: " + line);
                    continue;
                }
                entries.add(new UserEntry(line));
            }
        } catch (IOException err) {
            System.err.println("Error reading password file: " + err.getMessage());
            return null;
        }
        return entries;
    }

    private static void TryUsernamesAsPasswords(List<UserEntry> users, AtomicInteger crackedCount, int totalUsers) {
        for (UserEntry user : users) {
            if (user._isCracked) {
                continue;
            }
            if (crackedCount.get() == totalUsers) {
                return;
            }

            String currentGuess = user._username;
            if (currentGuess == null || currentGuess.isEmpty()) {
                continue;
            }

            String encryptedGuess = jcrypt.crypt(user._salt, currentGuess);
            if (user._encryptedPassword.equals(encryptedGuess)) {
                System.out.println(currentGuess);
                user._isCracked = true;
                crackedCount.incrementAndGet();
            }
        }
    }

    private static void TryMangledUsernames(List<UserEntry> users, AtomicInteger crackedCount, int totalUsers) {
        for (UserEntry user : users) {
            if (user._isCracked) {
                continue;
            }
            if (crackedCount.get() == totalUsers) {
                return;
            }

            String baseUsername = user._username;
            if (baseUsername == null || baseUsername.isEmpty()) {
                continue;
            }

            List<String> mangledUsernames = ApplyAllMangles(baseUsername);

            for (String currentGuess : mangledUsernames) {
                if (user._isCracked) {
                    break; // Password for this user found by another guess/thread
                }
                if (crackedCount.get() == totalUsers) {
                    return;
                }

                if (currentGuess == null || currentGuess.isEmpty()) {
                    continue;
                }

                String encryptedGuess = jcrypt.crypt(user._salt, currentGuess);
                if (user._encryptedPassword.equals(encryptedGuess)) {
                    System.out.println(currentGuess);
                    user._isCracked = true;
                    crackedCount.incrementAndGet();
                    break; // Move to the next user
                }
            }
        }
    }

    private static void TryWordCombinations(List<String> dictionary, List<UserEntry> users, AtomicInteger crackedCount,
            int totalUsers, int mangleLevel) {
        for (String baseWord : dictionary) {
            if (baseWord == null || baseWord.isEmpty()) {
                continue; // Skip empty words in dictionary
            }

            Set<String> wordsToTry = new HashSet<>();
            if (mangleLevel == 0) {
                wordsToTry.add(baseWord);
            } else if (mangleLevel == 1) {
                wordsToTry.addAll(ApplyAllMangles(baseWord));
            } else if (mangleLevel == 2) {
                List<String> firstMangles = ApplyAllMangles(baseWord);
                for (String m1Word : firstMangles) {
                    if (m1Word == null || m1Word.isEmpty()) {
                        continue; // Avoid mangling empty strings further
                    }
                    wordsToTry.addAll(ApplyAllMangles(m1Word));
                }
            }

            for (String currentGuess : wordsToTry) {
                if (currentGuess == null || currentGuess.isEmpty()) {
                    continue;
                }

                for (UserEntry user : users) {
                    if (user._isCracked) {
                        continue;
                    }

                    String encryptedGuess = jcrypt.crypt(user._salt, currentGuess);
                    if (user._encryptedPassword.equals(encryptedGuess)) {
                        System.out.println(currentGuess);
                        user._isCracked = true;
                        crackedCount.incrementAndGet();
                        if (crackedCount.get() == totalUsers) {
                            return;
                        }
                    }
                }
                if (crackedCount.get() == totalUsers) {
                    return;
                }
            }
            if (crackedCount.get() == totalUsers) {
                return;
            }
        }
    }

    private static List<String> ApplyAllMangles(String word) {
        Set<String> mangledWordsSet = new HashSet<>();

        // Prepend characters
        for (char ch : MangleChars) {
            mangledWordsSet.add(ch + word);
        }
        // Append characters
        for (char ch : MangleChars) {
            mangledWordsSet.add(word + ch);
        }
        // Delete first character
        if (word.length() > 0) {
            mangledWordsSet.add(word.substring(1));
        }
        // Delete last character
        if (word.length() > 0) {
            mangledWordsSet.add(word.substring(0, word.length() - 1));
        }
        // Reverse
        mangledWordsSet.add(new StringBuilder(word).reverse().toString());
        // Duplicate
        mangledWordsSet.add(word + word);
        // Reflect
        String reversedWord = new StringBuilder(word).reverse().toString();
        mangledWordsSet.add(word + reversedWord);
        mangledWordsSet.add(reversedWord + word);
        // Uppercase
        mangledWordsSet.add(word.toUpperCase());
        // Lowercase
        mangledWordsSet.add(word.toLowerCase());
        // Capitalize
        if (word.length() > 0) {
            mangledWordsSet.add(
                    Character.toUpperCase(word.charAt(0)) + (word.length() > 1 ? word.substring(1).toLowerCase() : ""));
        } else {
            mangledWordsSet.add("");
        }
        // nCapitalize
        if (word.length() > 0) {
            mangledWordsSet.add(
                    Character.toLowerCase(word.charAt(0)) + (word.length() > 1 ? word.substring(1).toUpperCase() : ""));
        } else {
            mangledWordsSet.add("");
        }
        // Toggle case 1 (StRiNg)
        mangledWordsSet.add(ToggleCase(word, true));
        // Toggle case 2 (sTrInG)
        mangledWordsSet.add(ToggleCase(word, false));

        // Filter out null or empty strings from mangling results
        mangledWordsSet.removeIf(s -> s == null || s.isEmpty());
        return new ArrayList<>(mangledWordsSet);
    }

    private static String ToggleCase(String word, boolean firstCharUpperPattern) {
        if (word == null || word.isEmpty()) {
            return "";
        }
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < word.length(); i++) {
            char c = word.charAt(i);
            if (Character.isLetter(c)) {
                boolean shouldBeUpper = (i % 2 == 0) ? firstCharUpperPattern : !firstCharUpperPattern;
                if (shouldBeUpper) {
                    stringBuilder.append(Character.toUpperCase(c));
                } else {
                    stringBuilder.append(Character.toLowerCase(c));
                }
            } else {
                stringBuilder.append(c);
            }
        }
        return stringBuilder.toString();
    }
}
