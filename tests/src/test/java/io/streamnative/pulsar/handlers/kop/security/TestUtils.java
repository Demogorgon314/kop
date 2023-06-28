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
package io.streamnative.pulsar.handlers.kop.security;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.util.List;

public class TestUtils {

    static File tempFile() {
        final File file;
        try {
            file = Files.createTempFile("kafka", ".tmp").toFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        file.deleteOnExit();
        return file;
    }

    static File tempDirectory() {
        final File file;
        try {
            file = Files.createTempDirectory("kafka-").toFile();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        file.deleteOnExit();
        return file;
    }

    public static File writeJaasContextsToFile(final List<JaasUtils.JaasSection> jaasSections) throws IOException {
        final File file = tempFile();
        try (Writer writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(jaasSections.stream().map(JaasUtils.JaasSection::toString).reduce((x, y) -> x + y).orElse(""));
        }
        return file;
    }
}
