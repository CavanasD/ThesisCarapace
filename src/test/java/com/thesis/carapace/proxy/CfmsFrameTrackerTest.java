package com.thesis.carapace.proxy;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CfmsFrameTrackerTest {

    private final CfmsFrameTracker tracker = new CfmsFrameTracker();

    @Test
    void inspectsOnlyFirstProcessFramePerLogicalStream() {
        byte[] firstControlFrame = frame(7, CfmsFrameTracker.PROCESS);
        byte[] followingFileChunk = frame(7, CfmsFrameTracker.PROCESS);

        assertTrue(tracker.shouldInspect("client-1", firstControlFrame));
        assertFalse(tracker.shouldInspect("client-1", followingFileChunk));
        assertTrue(tracker.shouldInspect("client-1", frame(9, CfmsFrameTracker.PROCESS)));
    }

    @Test
    void conclusionReleasesCompletedStream() {
        byte[] process = frame(11, CfmsFrameTracker.PROCESS);
        assertTrue(tracker.shouldInspect("client-1", process));

        tracker.onUpstreamFrame("client-1", frame(11, CfmsFrameTracker.CONCLUSION));

        assertTrue(tracker.shouldInspect("client-1", process));
    }

    @Test
    void neverInspectsNonProcessOrTruncatedFrames() {
        assertFalse(tracker.shouldInspect("client-1", frame(1, CfmsFrameTracker.CONCLUSION)));
        assertFalse(tracker.shouldInspect("client-1", new byte[4]));
    }

    private byte[] frame(int id, int type) {
        return new byte[] {
                (byte) (id >>> 24),
                (byte) (id >>> 16),
                (byte) (id >>> 8),
                (byte) id,
                (byte) type,
                1, 2, 3
        };
    }
}
