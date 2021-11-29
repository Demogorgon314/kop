/**
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.streamnative.pulsar.handlers.kop.format;

import com.google.common.annotations.VisibleForTesting;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.streamnative.pulsar.handlers.kop.utils.KopLogValidator;
import io.streamnative.pulsar.handlers.kop.utils.LongRef;
import java.util.List;
import java.util.Locale;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.bookkeeper.mledger.Entry;
import org.apache.kafka.common.record.CompressionType;
import org.apache.kafka.common.record.MemoryRecords;
import org.apache.kafka.common.record.RecordBatch;
import org.apache.kafka.common.record.TimestampType;
import org.apache.pulsar.common.api.proto.MessageMetadata;
import org.apache.pulsar.common.protocol.Commands;

/**
 * The entry formatter that uses Kafka's mixed versions format.
 * This formatter support all kafka magic version records,
 * so call it Mixed entry formatter.
 */
@Slf4j
public class KafkaMixedEntryFormatter extends AbstractEntryFormatter {

    @Getter
    @VisibleForTesting
    private final String brokerCompressionType;

    public KafkaMixedEntryFormatter(String brokerCompressionType) {
        this.brokerCompressionType = brokerCompressionType;
    }

    @Override
    public EncodeResult encode(final MemoryRecords records) {
        final int numMessages = EntryFormatter.parseNumMessages(records);
        final ByteBuf recordsWrapper = Unpooled.wrappedBuffer(records.buffer());
        final ByteBuf buf = Commands.serializeMetadataAndPayload(
                Commands.ChecksumType.None,
                getMessageMetadataWithNumberMessages(numMessages),
                recordsWrapper);
        recordsWrapper.release();

        return EncodeResult.get(records, buf, numMessages, 0);
    }

    @Override
    public DecodeResult decode(List<Entry> entries, byte magic) {
        return super.decode(entries, magic);
    }

    private static MessageMetadata getMessageMetadataWithNumberMessages(int numMessages) {
        final MessageMetadata metadata = new MessageMetadata();
        metadata.addProperty()
                .setKey(IDENTITY_KEY)
                .setValue(IDENTITY_VALUE);
        metadata.setProducerName("");
        metadata.setSequenceId(0L);
        metadata.setPublishTime(System.currentTimeMillis());
        metadata.setNumMessagesInBatch(numMessages);
        return metadata;
    }

}
