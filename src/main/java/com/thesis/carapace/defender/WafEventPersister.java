package com.thesis.carapace.defender;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDate;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

/**
 * Append-only JSONL persister for WAF events. Log files rotate daily under
 * {@code waf.log.dir} (default {@code ./waf-logs}); each line is one event
 * serialised by Jackson.
 *
 * <p>Persistence is fire-and-forget: events are queued onto a single-thread
 * executor so the request path never blocks on disk I/O. On startup the most
 * recent N entries from today's file are loaded back into memory so the
 * dashboard's ring buffer survives restarts.
 *
 * <p>Backup uses {@link #snapshotAll()} which copies every log file currently
 * on disk into a single zip — see {@link com.thesis.carapace.api.WafController}.
 */
@Slf4j
@Component
public class WafEventPersister {

    @Value("${waf.log.dir:./waf-logs}")
    private String logDirProperty;

    @Value("${waf.backup.dir:./waf-backups}")
    private String backupDirProperty;

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final ExecutorService writer = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "waf-persister");
        t.setDaemon(true);
        return t;
    });

    private Path logDir() {
        Path p = Paths.get(logDirProperty);
        try {
            Files.createDirectories(p);
        } catch (IOException e) {
            log.warn("[WAF-PERSIST] Could not create log dir {}: {}", p, e.getMessage());
        }
        return p;
    }

    private Path backupDir() {
        Path p = Paths.get(backupDirProperty);
        try {
            Files.createDirectories(p);
        } catch (IOException e) {
            log.warn("[WAF-PERSIST] Could not create backup dir {}: {}", p, e.getMessage());
        }
        return p;
    }

    private Path fileForToday() {
        return logDir().resolve("waf-events-" + LocalDate.now() + ".jsonl");
    }

    /** Queue an event for asynchronous persistence. */
    public void persist(WafEvent event) {
        writer.submit(() -> writeOne(event));
    }

    private void writeOne(WafEvent event) {
        try {
            String line = mapper.writeValueAsString(event) + System.lineSeparator();
            Files.writeString(
                    fileForToday(),
                    line,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            log.warn("[WAF-PERSIST] Failed to persist event {}: {}",
                    event.encryptedId(), e.getMessage());
        }
    }

    /**
     * Tail the last {@code limit} entries from today's file. Older days are
     * not loaded — they're available via the backup endpoint if needed.
     * Returns oldest-first so callers can append in chronological order.
     */
    public List<WafEvent> loadRecent(int limit) {
        Path file = fileForToday();
        if (!Files.exists(file)) return List.of();

        Deque<String> tail = new ArrayDeque<>(limit);
        try (Stream<String> lines = Files.lines(file)) {
            lines.forEach(line -> {
                if (tail.size() == limit) tail.pollFirst();
                tail.offerLast(line);
            });
        } catch (IOException e) {
            log.warn("[WAF-PERSIST] Failed to read {}: {}", file, e.getMessage());
            return List.of();
        }

        List<WafEvent> events = new ArrayList<>(tail.size());
        for (String line : tail) {
            try {
                events.add(mapper.readValue(line, WafEvent.class));
            } catch (IOException e) {
                // Skip malformed lines silently — operator can grep manually.
            }
        }
        return events;
    }

    /** List the file names of all log files currently on disk (sorted). */
    public List<String> listLogFiles() {
        Path dir = logDir();
        try (Stream<Path> entries = Files.list(dir)) {
            List<String> names = entries
                    .filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith("waf-events-") && n.endsWith(".jsonl"))
                    .sorted()
                    .toList();
            return names;
        } catch (IOException e) {
            return List.of();
        }
    }

    /**
     * Bundle every log file currently on disk into a timestamped zip under
     * {@code waf.backup.dir}. Returns the created file path so callers can
     * surface it as a download link.
     */
    public Path snapshotAll() throws IOException {
        Path target = backupDir().resolve(
                "waf-backup-" + System.currentTimeMillis() + ".zip");
        try (OutputStream fos = Files.newOutputStream(target);
             java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(fos)) {
            for (String name : listLogFiles()) {
                Path src = logDir().resolve(name);
                if (!Files.exists(src)) continue;
                zos.putNextEntry(new java.util.zip.ZipEntry(name));
                Files.copy(src, zos);
                zos.closeEntry();
            }
        }
        return target;
    }

    /** List backup file names (most recent first). */
    public List<String> listBackups() {
        Path dir = backupDir();
        try (Stream<Path> entries = Files.list(dir)) {
            List<String> names = new ArrayList<>(entries
                    .filter(Files::isRegularFile)
                    .map(p -> p.getFileName().toString())
                    .filter(n -> n.startsWith("waf-backup-") && n.endsWith(".zip"))
                    .toList());
            Collections.reverse(names);
            return names;
        } catch (IOException e) {
            return List.of();
        }
    }

    /** Resolve a backup file by name, returning null when missing or escaping. */
    public Path resolveBackup(String name) {
        if (name == null || name.contains("/") || name.contains("\\") || name.contains("..")) {
            return null;
        }
        Path candidate = backupDir().resolve(name);
        return Files.exists(candidate) ? candidate : null;
    }

    @PreDestroy
    void shutdown() {
        writer.shutdown();
        try {
            writer.awaitTermination(5, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
