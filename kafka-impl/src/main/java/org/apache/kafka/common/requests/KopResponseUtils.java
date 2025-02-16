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
package org.apache.kafka.common.requests;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import java.nio.ByteBuffer;
import lombok.extern.slf4j.Slf4j;

/**
 * Provide util classes to access protected fields in kafka structures.
 */
@Slf4j
public class KopResponseUtils {

    /**
     * Serialize a kafka response into a byte buf.
     * @param version
     * @param responseHeader
     * @param response
     * @return
     */
    public static ByteBuf serializeResponse(short version,
                                            ResponseHeader responseHeader,
                                            AbstractResponse response) {
        return Unpooled.wrappedBuffer(response.serializeWithHeader(responseHeader, version));
    }

    public static ByteBuffer serializeRequest(RequestHeader requestHeader, AbstractRequest request) {
        return RequestUtils.serialize(requestHeader.data(), requestHeader.headerVersion(),
                request.data(), request.version());
    }

}
