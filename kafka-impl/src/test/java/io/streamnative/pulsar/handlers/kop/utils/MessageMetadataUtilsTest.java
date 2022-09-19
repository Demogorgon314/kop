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
package io.streamnative.pulsar.handlers.kop.utils;

import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Test unit for {@link MessageMetadataUtils}.
 */
public class MessageMetadataUtilsTest {

    @Test
    public void testGetMockOffset() {
        final int N = 1000;
        final int M = 1000;
        long[] arr = new long[N * M];
        int next = 0;
        for (int i = 0; i < N; i++) {
            for (int j = 0; j < M; j++) {
                long mockOffset = MessageMetadataUtils.getMockOffset(i, j);
                arr[next++] = mockOffset;
            }
        }
        for (int i = 1; i < arr.length; i++) {
            assertTrue(arr[i - 1] < arr[i], String.format("The arr[%d]=%s >= arr[%d]=%s",
                    i - 1, arr[i - 1], i, arr[i]));
        }
    }
}