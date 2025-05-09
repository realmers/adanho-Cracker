import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

public class PasswordCrackMultiThread {

    private static class UserEntry {
        String username;
        String salt;
        String encryptedPassword;
        volatile boolean isCracked = false; // Volatile for visibility across threads

        UserEntry(String line) {
            // Assumes line is pre-validated by loadPasswordEntries
            String[] parts = line.split(":", 3); // account:hash:rest
            this.username = parts[0];
            this.salt = parts[1].substring(0, 2);
            this.encryptedPassword = parts[1];
        }
    }

    private static final char[] MANGLE_CHARS;
    static {
        List<Character> chars = new ArrayList<>();
        for (char c = 'a'; c <= 'z'; c++) chars.add(c);
        for (char c = 'A'; c <= 'Z'; c++) chars.add(c);
        for (char c = '0'; c <= '9'; c++) chars.add(c);
        MANGLE_CHARS = new char[chars.size()];
        for (int i = 0; i < chars.size(); i++) MANGLE_CHARS[i] = chars.get(i);
    }

    private static final Object PRINT_LOCK = new Object();
    private static AtomicInteger crackedCount;
    private static AtomicBoolean allPasswordsCracked;
    private static int totalUsers;
    private static List<UserEntry> users;

    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("Usage: java PasswordCrackMultiThread <dictionary_file> <password_file>");
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

        List<String> dictionary = loadDictionary(dictionaryFile);
        users = loadPasswordEntries(passwordFile);

        if (dictionary == null || users == null) {
            System.exit(1);
        }
        if (dictionary.isEmpty()) {
            System.err.println("Error: Dictionary is empty.");
            System.exit(1);
        }
        if (users.isEmpty()) {
            System.err.println("Error: No user entries loaded from password file.");
            System.exit(1);
        }

        totalUsers = users.size();
        crackedCount = new AtomicInteger(0);
        allPasswordsCracked = new AtomicBoolean(false);

        int numThreads = Runtime.getRuntime().availableProcessors();
        ExecutorService executor = Executors.newFixedThreadPool(numThreads);

        for (int mangleLevel = 0; mangleLevel <= 2; mangleLevel++) {
            if (allPasswordsCracked.get()) break;

            List<List<String>> dictionaryChunks = splitDictionary(dictionary, numThreads);
            for (List<String> chunk : dictionaryChunks) {
                final int currentMangleLevel = mangleLevel; // Effectively final for lambda
                executor.submit(() -> processDictionaryChunk(chunk, currentMangleLevel));
            }
            
            // Wait for tasks of this level to make progress, but allow early exit
            // This is a simplified wait; a more robust solution might use CountDownLatch per level
            // For now, we rely on allPasswordsCracked flag and executor shutdown.
            // The main thread will proceed to submit next level tasks if not all cracked.
            // We need a way to ensure one level's tasks are mostly done or all cracked before next.
            // However, the problem asks to run until all found, so overlapping levels is fine if it finds them faster.
            // Let's refine: we should wait for a level to complete before starting the next, unless all are cracked.
            // This requires a different task submission/completion tracking.
            // For simplicity of this example, we'll let tasks run and check allPasswordsCracked.
            // A full shutdown and await termination is better after each level if strict ordering is desired.
        }
        
        // Wait for all submitted tasks to complete or for an early shutdown
        executor.shutdown();
        try {
            // Wait for existing tasks to terminate.
            // If allPasswordsCracked becomes true, tasks should self-terminate.
            // Give a generous timeout for tasks to finish.
            if (!executor.awaitTermination(24, TimeUnit.HOURS)) {
                System.err.println("Warning: Tasks did not complete within the timeout.");
                executor.shutdownNow(); // Force shutdown
            }
        } catch (InterruptedException ie) {
            System.err.println("Warning: Main thread interrupted during awaitTermination.");
            executor.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }
    
    private static void processDictionaryChunk(List<String> dictionaryChunk, int mangleLevel) {
        for (String baseWord : dictionaryChunk) {
            if (allPasswordsCracked.get()) return; // Early exit if all passwords found
            if (baseWord == null || baseWord.isEmpty()) continue;

            Set<String> wordsToTry = new HashSet<>();
            if (mangleLevel == 0) {
                wordsToTry.add(baseWord);
            } else if (mangleLevel == 1) {
                wordsToTry.addAll(applyAllMangles(baseWord));
            } else if (mangleLevel == 2) {
                List<String> firstMangles = applyAllMangles(baseWord);
                for (String m1Word : firstMangles) {
                    if (allPasswordsCracked.get()) return;
                    if (m1Word == null || m1Word.isEmpty()) continue;
                    wordsToTry.addAll(applyAllMangles(m1Word));
                }
            }

            for (String currentGuess : wordsToTry) {
                if (allPasswordsCracked.get()) return;
                if (currentGuess == null || currentGuess.isEmpty()) continue;

                for (UserEntry user : users) {
                    if (allPasswordsCracked.get()) return;
                    if (user.isCracked) continue; // Quick check (volatile read)

                    String encryptedGuess = jcrypt.crypt(user.salt, currentGuess);

                    if (user.encryptedPassword.equals(encryptedGuess)) { // Check hash first
                        synchronized (user) { // Synchronize on the specific user entry
                            if (!user.isCracked) { // Double-check under lock
                                user.isCracked = true; // Set volatile field under lock
                                
                                synchronized (PRINT_LOCK) {
                                    System.out.println(currentGuess);
                                }
                                
                                if (crackedCount.incrementAndGet() == totalUsers) {
                                    allPasswordsCracked.set(true);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private static List<List<String>> splitDictionary(List<String> dictionary, int numChunks) {
        List<List<String>> chunks = new ArrayList<>();
        if (dictionary.isEmpty() || numChunks <= 0) return chunks;

        int totalSize = dictionary.size();
        int chunkSize = (int) Math.ceil((double) totalSize / numChunks);
        if (chunkSize == 0 && totalSize > 0) chunkSize = 1; // Ensure progress for small dictionaries

        for (int i = 0; i < totalSize; i += chunkSize) {
            chunks.add(new ArrayList<>(dictionary.subList(i, Math.min(totalSize, i + chunkSize))));
        }
        return chunks;
    }

    private static List<String> loadDictionary(String filePath) {
        try {
            return Files.readAllLines(Paths.get(filePath));
        } catch (IOException e) {
            System.err.println("Error reading dictionary file: " + e.getMessage());
            return null;
        }
    }

    private static List<UserEntry> loadPasswordEntries(String filePath) {
        List<UserEntry> entries = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                String[] parts = line.split(":");
                if (parts.length < 2 || parts[1].length() < 2) {
                    System.err.println("Warning: Skipping malformed line in password file: " + line);
                    continue;
                }
                entries.add(new UserEntry(line));
            }
        } catch (IOException e) {
            System.err.println("Error reading password file: " + e.getMessage());
            return null;
        }
        return entries;
    }

    private static List<String> applyAllMangles(String word) {
        Set<String> mangledWordsSet = new HashSet<>();
        // Prepend characters
        for (char ch : MANGLE_CHARS) {
            mangledWordsSet.add(ch + word);
        }
        // Append characters
        for (char ch : MANGLE_CHARS) {
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
            mangledWordsSet.add(Character.toUpperCase(word.charAt(0)) + (word.length() > 1 ? word.substring(1).toLowerCase() : ""));
        } else {
            mangledWordsSet.add("");
        }
        // nCapitalize
        if (word.length() > 0) {
            mangledWordsSet.add(Character.toLowerCase(word.charAt(0)) + (word.length() > 1 ? word.substring(1).toUpperCase() : ""));
        } else {
            mangledWordsSet.add("");
        }
        // Toggle case 1 (StRiNg)
        mangledWordsSet.add(toggleCase(word, true));
        // Toggle case 2 (sTrInG)
        mangledWordsSet.add(toggleCase(word, false));
        
        mangledWordsSet.removeIf(s -> s == null || s.isEmpty());
        return new ArrayList<>(mangledWordsSet);
    }

    private static String toggleCase(String word, boolean firstCharUpperPattern) {
        if (word == null || word.isEmpty()) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < word.length(); i++) {
            char c = word.charAt(i);
            if (Character.isLetter(c)) {
                boolean shouldBeUpper = (i % 2 == 0) ? firstCharUpperPattern : !firstCharUpperPattern;
                if (shouldBeUpper) {
                    sb.append(Character.toUpperCase(c));
                } else {
                    sb.append(Character.toLowerCase(c));
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }
}
