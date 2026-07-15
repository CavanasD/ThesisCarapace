package com.thesis.carapace.defender;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
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
import java.time.ZoneId;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;

/**
 * Bounded, batched JSONL persistence for WAF control-plane events. Producers
 * never wait for disk: a full queue drops the new event and increments an
 * observable counter instead of allowing file traffic to exhaust heap.
 */
@Slf4j
@Component
public class WafEventPersister {

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());
    private final Path logDir;
    private final Path backupDir;
    private final BlockingQueue<WafEvent> queue;
    private final int queueCapacity;
    private final int batchSize;
    private final long flushIntervalMs;
    private final AtomicBoolean running = new AtomicBoolean();
    private final AtomicLong droppedEvents = new AtomicLong();
    private final AtomicLong persistedEvents = new AtomicLong();
    private final AtomicLong writeFailures = new AtomicLong();
    private Thread writerThread;

    public WafEventPersister(
            MeterRegistry meterRegistry,
            @Value("${waf.log.dir:./waf-logs}") String logDir,
            @Value("${waf.backup.dir:./waf-backups}") String backupDir,
            @Value("${waf.persistence.queue-capacity:4096}") int queueCapacity,
            @Value("${waf.persistence.batch-size:100}") int batchSize,
            @Value("${waf.persistence.flush-interval-ms:250}") long flushIntervalMs) {
        if (queueCapacity < 1 || batchSize < 1 || flushIntervalMs < 1) {
            throw new IllegalArgumentException("WAF persistence queue, batch and flush settings must be positive");
        }
        this.logDir = Paths.get(logDir);
        this.backupDir = Paths.get(backupDir);
        this.queueCapacity = queueCapacity;
        this.queue = new ArrayBlockingQueue<>(queueCapacity);
        this.batchSize = Math.min(batchSize, queueCapacity);
        this.flushIntervalMs = flushIntervalMs;

        Gauge.builder("carapace.waf.persistence.queue.depth", queue, BlockingQueue::size)
                .description("WAF events waiting for batched persistence")
                .register(meterRegistry);
        Gauge.builder("carapace.waf.persistence.queue.capacity", this, ignored -> queueCapacity)
                .description("Maximum WAF persistence queue depth")
                .register(meterRegistry);
        Gauge.builder("carapace.waf.persistence.events.dropped", droppedEvents, AtomicLong::get)
                .description("WAF events dropped because the persistence queue was full")
                .register(meterRegistry);
        Gauge.builder("carapace.waf.persistence.events.persisted", persistedEvents, AtomicLong::get)
                .description("WAF events persisted to JSONL")
                .register(meterRegistry);
        Gauge.builder("carapace.waf.persistence.write.failures", writeFailures, AtomicLong::get)
                .description("WAF event persistence failures")
                .register(meterRegistry);
    }

    @PostConstruct
    void start() {
        if (!running.compareAndSet(false, true)) return;
        writerThread = new Thread(this::writerLoop, "waf-persister");
        writerThread.setDaemon(true);
        writerThread.start();
    }

    /** Enqueue without blocking the gateway request path. */
    public void persist(WafEvent event) {
        if (queue.offer(event)) return;
        long dropped = droppedEvents.incrementAndGet();
        if (dropped == 1 || dropped % 100 == 0) {
            log.warn("[WAF-PERSIST] Queue full (capacity={}); dropped {} event(s)", queueCapacity, dropped);
        }
    }

    private void writerLoop() {
        List<WafEvent> batch = new ArrayList<>(batchSize);
        while (running.get() || !queue.isEmpty()) {
            try {
                WafEvent first = queue.poll(flushIntervalMs, TimeUnit.MILLISECONDS);
                if (first == null) continue;
                batch.add(first);
                queue.drainTo(batch, batchSize - 1);
                writeBatch(batch);
                batch.clear();
            } catch (InterruptedException ignored) {
                // Shutdown interrupts the wait so the remaining queue can drain.
            } catch (RuntimeException e) {
                writeFailures.incrementAndGet();
                log.warn("[WAF-PERSIST] Unexpected writer failure: {}", e.getMessage());
                batch.clear();
            }
        }
    }

    private void writeBatch(List<WafEvent> events) {
        Map<LocalDate, StringBuilder> linesByDay = new LinkedHashMap<>();
        Map<LocalDate, Integer> countsByDay = new LinkedHashMap<>();
        for (WafEvent event : events) {
            try {
                LocalDate day = LocalDate.ofInstant(event.timestamp(), ZoneId.systemDefault());
                linesByDay.computeIfAbsent(day, ignored -> new StringBuilder())
                        .append(mapper.writeValueAsString(event))
                        .append(System.lineSeparator());
                countsByDay.merge(day, 1, Integer::sum);
            } catch (IOException e) {
                writeFailures.incrementAndGet();
                log.warn("[WAF-PERSIST] Could not serialize event {}: {}",
                        event.encryptedId(), e.getMessage());
            }
        }

        ensureDirectory(logDir);
        linesByDay.forEach((day, lines) -> {
            int count = countsByDay.getOrDefault(day, 0);
            try {
                Files.writeString(fileFor(day), lines, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
                persistedEvents.addAndGet(count);
            } catch (IOException e) {
                writeFailures.addAndGet(count);
                log.warn("[WAF-PERSIST] Failed to persist {} event(s): {}", count, e.getMessage());
            }
        });
    }

    public List<WafEvent> loadRecent(int limit) {
        if (limit <= 0) return List.of();
        Path file = fileFor(LocalDate.now());
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
            } catch (IOException ignored) {
                // Skip malformed lines; existing logs remain operator-readable.
            }
        }
        return events;
    }

    public List<String> listLogFiles() {
        ensureDirectory(logDir);
        try (Stream<Path> entries = Files.list(logDir)) {
            return entries
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.startsWith("waf-events-") && name.endsWith(".jsonl"))
                    .sorted()
                    .toList();
        } catch (IOException e) {
            return List.of();
        }
    }

    public Path snapshotAll() throws IOException {
        ensureDirectory(backupDir);
        Path target = backupDir.resolve("waf-backup-" + System.currentTimeMillis() + ".zip");
        try (OutputStream output = Files.newOutputStream(target);
             java.util.zip.ZipOutputStream zip = new java.util.zip.ZipOutputStream(output)) {
            for (String name : listLogFiles()) {
                Path source = logDir.resolve(name);
                if (!Files.exists(source)) continue;
                zip.putNextEntry(new java.util.zip.ZipEntry(name));
                Files.copy(source, zip);
                zip.closeEntry();
            }
        }
        return target;
    }

    public List<String> listBackups() {
        ensureDirectory(backupDir);
        try (Stream<Path> entries = Files.list(backupDir)) {
            List<String> names = new ArrayList<>(entries
                    .filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .filter(name -> name.startsWith("waf-backup-") && name.endsWith(".zip"))
                    .sorted()
                    .toList());
            Collections.reverse(names);
            return names;
        } catch (IOException e) {
            return List.of();
        }
    }

    public Path resolveBackup(String name) {
        if (name == null || name.contains("/") || name.contains("\\") || name.contains("..")) {
            return null;
        }
        Path candidate = backupDir.resolve(name);
        return Files.isRegularFile(candidate) ? candidate : null;
    }

    public long getQueueDepth() { return queue.size(); }
    public long getQueueCapacity() { return queueCapacity; }
    public long getDroppedEvents() { return droppedEvents.get(); }
    public long getPersistedEvents() { return persistedEvents.get(); }
    public long getWriteFailures() { return writeFailures.get(); }

    private Path fileFor(LocalDate day) {
        return logDir.resolve("waf-events-" + day + ".jsonl");
    }

    private void ensureDirectory(Path directory) {
        try {
            Files.createDirectories(directory);
        } catch (IOException e) {
            log.warn("[WAF-PERSIST] Could not create directory {}: {}", directory, e.getMessage());
        }
    }

    @PreDestroy
    void shutdown() {
        if (!running.getAndSet(false)) return;
        if (writerThread == null) return;
        writerThread.interrupt();
        try {
            writerThread.join(5000);
            if (writerThread.isAlive()) {
                log.warn("[WAF-PERSIST] Writer did not drain within shutdown timeout; queueDepth={}", queue.size());
            }
        } catch (InterruptedException ignored) {
            Thread.currentThread().interrupt();
        }
    }
}
