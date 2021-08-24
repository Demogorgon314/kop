package io.streamnative.pulsar.handlers.kop.format;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.record.MemoryRecords;
import org.apache.kafka.common.record.MemoryRecordsBuilder;
import org.apache.kafka.common.record.RecordBatch;
import org.apache.kafka.common.record.SimpleRecord;
import org.apache.kafka.common.record.TimestampType;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Threads;
import org.openjdk.jmh.annotations.Warmup;

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 5)
@Threads(4)
@Fork(1)
@State(value = Scope.Benchmark)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
public class EncodePerformanceJmhTest {

    @Param({"2048", "4096", "8192"})
    private int numMessages;

    @Param({"1024","2048", "4096", "8192"})
    private int messageSize;

    final EntryFormatter pulsarFormatter = EntryFormatterFactory.create("pulsar");
    final EntryFormatter kafkaFormatter = EntryFormatterFactory.create("kafka");

    private MemoryRecords fixedRecords;
    private MemoryRecords randomRecords;


    @Setup(Level.Trial)
    public void setup() {
        fixedRecords = prepareFixedRecords();
        randomRecords = prepareRandomRecords();
    }

    @Benchmark
    public boolean testPulsarFormatterFixedRecords() {
        return pulsarFormatter.encode(fixedRecords, numMessages).release();
    }

    @Benchmark
    public boolean testPulsarFormatterRandomRecords() {
        return pulsarFormatter.encode(randomRecords, numMessages).release();
    }

    @Benchmark
    public boolean testKafkaFormatterFixedRecords() {
        return kafkaFormatter.encode(fixedRecords, numMessages).release();
    }

    @Benchmark
    public boolean testKafkaFormatterRandomRecords() {
        return kafkaFormatter.encode(randomRecords, numMessages).release();
    }


    private static MemoryRecordsBuilder newMemoryRecordsBuilder() {
        return MemoryRecords.builder(
                ByteBuffer.allocate(1024 * 1024 * 5),
                RecordBatch.CURRENT_MAGIC_VALUE,
                CompressionType.NONE,
                TimestampType.CREATE_TIME,
                0L);
    }

    private MemoryRecords prepareFixedRecords() {
        final MemoryRecordsBuilder builder = newMemoryRecordsBuilder();
        for (int i = 0; i < numMessages; i++) {
            final byte[] value = new byte[messageSize];
            Arrays.fill(value, (byte) 'a');
            builder.append(new SimpleRecord(System.currentTimeMillis(), "key".getBytes(), value));
        }
        return builder.build();
    }

    private MemoryRecords prepareRandomRecords() {
        final MemoryRecordsBuilder builder = newMemoryRecordsBuilder();
        final Random random = new Random();
        for (int i = 0; i < numMessages; i++) {
            final ByteBuffer buffer = ByteBuffer.allocate(messageSize);
            for (int j = 0; j < messageSize / 4; j++) {
                buffer.putInt(random.nextInt());
            }
            builder.append(new SimpleRecord(System.currentTimeMillis(), "key".getBytes(), buffer.array()));
        }
        return builder.build();
    }
}
