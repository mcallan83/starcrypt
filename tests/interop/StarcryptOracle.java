// Test-only adapter to the unmodified libraries bundled with Cryptomator.
// No cryptography or mounting is implemented here.
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParser;
import org.cryptomator.cryptofs.CryptoFileSystemProperties;
import org.cryptomator.cryptofs.CryptoFileSystemProvider;
import org.cryptomator.cryptolib.api.CryptorProvider;
import org.cryptomator.cryptolib.api.AuthenticationFailedException;
import org.cryptomator.cryptolib.api.Masterkey;
import org.cryptomator.cryptolib.common.MasterkeyFileAccess;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class StarcryptOracle {
    private static String normalized(String value) {
        return Normalizer.normalize(value, Normalizer.Form.NFC);
    }

    private static List<Path> sourceEntries(Path source) throws Exception {
        try (var paths = Files.walk(source)) {
            return paths.filter(path -> !path.equals(source))
                    .sorted(Comparator.comparingInt(Path::getNameCount)
                            .thenComparing(Path::toString))
                    .toList();
        }
    }

    private static String relativeName(Path source, Path path) {
        return normalized(source.relativize(path).toString());
    }

    private static void importSource(FileSystem vault, Path source) throws Exception {
        for (var entry : sourceEntries(source)) {
            var destination = vault.getPath("/" + relativeName(source, entry));
            if (Files.isSymbolicLink(entry)) {
                Files.createSymbolicLink(destination, vault.getPath(Files.readSymbolicLink(entry).toString()));
            } else if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                Files.createDirectories(destination);
            } else {
                Files.copy(entry, destination);
            }
        }
    }

    private static List<Map<String, String>> verifySource(FileSystem vault, Path source) throws Exception {
        var entries = sourceEntries(source);
        Set<String> expected = new HashSet<>();
        for (var entry : entries) {
            if (!expected.add(relativeName(source, entry))) {
                throw new AssertionError("Normalized filename collision in fixture");
            }
        }
        Set<String> actual = new HashSet<>();
        try (var paths = Files.walk(vault.getPath("/"))) {
            paths.filter(path -> !path.toString().equals("/"))
                    .forEach(path -> actual.add(normalized(path.toString().substring(1))));
        }
        if (!actual.equals(expected)) {
            throw new AssertionError("Official directory listing differs from source entries");
        }
        var checked = new ArrayList<Map<String, String>>();
        for (var entry : entries) {
            String name = relativeName(source, entry);
            var destination = vault.getPath("/" + name);
            String type;
            if (Files.isSymbolicLink(entry)) {
                type = "symlink";
                if (!Files.isSymbolicLink(destination)
                        || !Files.readSymbolicLink(entry).toString().equals(Files.readSymbolicLink(destination).toString())) {
                    throw new AssertionError("Symlink mismatch: " + name);
                }
            } else if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                type = "directory";
                if (!Files.isDirectory(destination, LinkOption.NOFOLLOW_LINKS)) {
                    throw new AssertionError("Directory mismatch: " + name);
                }
            } else {
                type = "file";
                if (!Files.isRegularFile(destination, LinkOption.NOFOLLOW_LINKS)
                        || Files.mismatch(entry, destination) != -1) {
                    throw new AssertionError("File mismatch: " + name);
                }
            }
            checked.add(Map.of("name", name, "type", type));
        }
        return checked;
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 6 || !(args[0].equals("create") || args[0].equals("verify") || args[0].equals("reject-corrupt"))) {
            throw new IllegalArgumentException("Usage: StarcryptOracle create|verify|reject-corrupt VAULT SOURCE SCHEME PASSWORD_FILE REPORT");
        }
        boolean create = args[0].equals("create");
        boolean rejectCorrupt = args[0].equals("reject-corrupt");
        var vault = Path.of(args[1]).toAbsolutePath();
        var source = Path.of(args[2]).toAbsolutePath();
        var scheme = CryptorProvider.Scheme.valueOf(args[3]);
        // Match the desktop password field's NFC convention.
        var password = normalized(Files.readString(Path.of(args[4]), StandardCharsets.UTF_8));
        var access = new MasterkeyFileAccess(new byte[0], new SecureRandom());
        if (create) {
            Files.createDirectory(vault);
        }
        List<Map<String, String>> checked;
        try (Masterkey key = create ? Masterkey.generate(new SecureRandom())
                : access.load(vault.resolve("masterkey.cryptomator"), password)) {
            if (create) {
                access.persist(key, vault.resolve("masterkey.cryptomator"), password);
            }
            var properties = CryptoFileSystemProperties.cryptoFileSystemProperties()
                    .withKeyLoader(ignored -> key.copy()).withCipherCombo(scheme).build();
            if (create) {
                CryptoFileSystemProvider.initialize(vault, properties, URI.create("masterkeyfile:masterkey.cryptomator"));
            }
            try (var fileSystem = CryptoFileSystemProvider.newFileSystem(vault, properties)) {
                if (create) {
                    importSource(fileSystem, source);
                }
                if (rejectCorrupt) {
                    try {
                        verifySource(fileSystem, source);
                        throw new AssertionError("Corruption was accepted by official libraries");
                    } catch (Exception failure) {
                        // A bad password, missing path, or unrelated I/O failure must
                        // never be mistaken for successful corruption detection.
                        boolean authenticatedFailure = false;
                        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
                            if (cause instanceof AuthenticationFailedException) {
                                authenticatedFailure = true;
                            }
                        }
                        if (!authenticatedFailure) {
                            throw failure;
                        }
                        checked = List.of(Map.of("rejection", "AuthenticationFailedException"));
                    }
                } else {
                    checked = verifySource(fileSystem, source);
                }
            }
        }
        var token = Files.readString(vault.resolve("vault.cryptomator")).split("\\.");
        var claims = JsonParser.parseString(new String(Base64.getUrlDecoder().decode(token[1]), StandardCharsets.UTF_8));
        String actualScheme = claims.getAsJsonObject().get("cipherCombo").getAsString();
        var report = Map.of("pass", true, "action", args[0], "scheme", actualScheme, "checked", checked, "corruption_rejected", rejectCorrupt,
                "java_version", System.getProperty("java.version"));
        Files.writeString(Path.of(args[5]), new GsonBuilder().setPrettyPrinting().create().toJson(report) + "\n");
        System.out.printf("Official Java %s: PASS (%d entries, %s)%n", args[0], checked.size(), actualScheme);
    }
}
