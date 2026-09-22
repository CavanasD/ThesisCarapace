package com.thesis.carapace.defender;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WafEventPersisterTest {

    @TempDir
    Path temporaryDirectory;

    @Test
    void boundedQueueDropsInsteadOfGrowingWithoutLimit() {
        WafEventPersister persister = persister(1, 1);

        persister.persist(event(1));
        persister.persist(event(2));

        assertEquals(1, persister.getQueueDepth());
        assertEquals(1, persister.getDroppedEvents());
    }

    @Test
    void shutdownDrainsBatchToJsonLines() {
        WafEventPersister persister = persister(10, 10);
        persister.start();
        persister.persist(event(1));
        persister.persist(event(2));
        persister.persist(event(3));

        persister.shutdown();

        assertEquals(0, persister.getQueueDepth());
        assertEquals(3, persister.getPersistedEvents());
        assertEquals(3, persister.loadRecent(10).size());
    }

    private WafEventPersister persister(int capacity, int batchSize) {
        return new WafEventPersister(
                new SimpleMeterRegistry(),
                temporaryDirectory.resolve("logs").toString(),
                temporaryDirectory.resolve("backups").toString(),
                capacity,
                batchSize,
                10);
    }

    private WafEvent event(long id) {
        return new WafEvent(id, "WAF-" + id, "ALLOWED", Instant.now(),
                "127.0.0.1", "test", false, null, null, null);
    }
}
