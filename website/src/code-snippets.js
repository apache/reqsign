/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

function dedent(lines) {
  const indents = lines
    .filter((l) => l.trim().length > 0)
    .map((l) => l.match(/^[ \t]*/)[0].length);
  const min = indents.length ? Math.min(...indents) : 0;
  return lines.map((l) => l.slice(min));
}

function extractRegion(content, region, file) {
  const lines = content.split("\n");
  const start = new RegExp(`ANCHOR:\\s*${region}\\b`);
  const end = new RegExp(`ANCHOR_END:\\s*${region}\\b`);
  let from = -1;
  let to = -1;
  for (let i = 0; i < lines.length; i++) {
    if (from === -1 && start.test(lines[i])) {
      from = i + 1;
    } else if (from !== -1 && end.test(lines[i])) {
      to = i;
      break;
    }
  }
  if (from === -1 || to === -1) {
    throw new Error(`remark-include-code: region "${region}" not found in ${file}`);
  }
  return dedent(lines.slice(from, to)).join("\n").replace(/^\n+|\s+$/g, "");
}

function stripLicenseHeader(content) {
  // Drop a leading block of comment/blank lines (the ASF header) so it does not
  // show up in the rendered snippet.
  const lines = content.split("\n");
  let i = 0;
  while (
    i < lines.length &&
    (lines[i].trim() === "" || /^\s*(\/\/|#|--|\/\*|\*)/.test(lines[i]))
  ) {
    i++;
  }
  return lines.slice(i).join("\n").replace(/^\n+|\s+$/g, "");
}

// Both the landing page and docs render the same compiled source files.
function codeSnippet(content, region) {
  return region
    ? extractRegion(content, region, "code snippet")
    : stripLicenseHeader(content)
        .split("\n")
        .filter((line) => !/^\s*\/\/ ANCHOR(?:_END)?:/.test(line))
        .join("\n");
}
module.exports = { codeSnippet };
