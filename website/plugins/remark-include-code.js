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

// A remark plugin that fills fenced code blocks from real example files, so the
// snippets shown in the docs are slices of code that CI actually compiles and
// runs. Usage in markdown:
//
//   ```rust file=core/examples/getting-started/src/main.rs region=quickstart
//   ```
//
// `file` is resolved from the repository root. `region` (optional) extracts the
// lines between `ANCHOR: <name>` and `ANCHOR_END: <name>` markers in the file —
// language-agnostic, so it works with //, #, --, etc. Without a region, the
// whole file is used with any leading license-header comment block stripped.

const fs = require("fs");
const path = require("path");

// website/plugins -> website -> repository root.
const ROOT = path.resolve(__dirname, "..", "..");

function parseMeta(meta) {
  const out = {};
  for (const m of meta.matchAll(/(\w+)=("[^"]*"|\S+)/g)) {
    out[m[1]] = m[2].replace(/^"|"$/g, "");
  }
  return out;
}

const { codeSnippet } = require("../src/code-snippets");

function transform(node) {
  if (
    node.type === "code" &&
    typeof node.meta === "string" &&
    /(^|\s)file=/.test(node.meta)
  ) {
    const opts = parseMeta(node.meta);
    const abs = path.resolve(ROOT, opts.file);
    const content = fs.readFileSync(abs, "utf8");
    node.value = codeSnippet(content, opts.region);
    const meta = node.meta
      .replace(/\s*file=("[^"]*"|\S+)/, "")
      .replace(/\s*region=("[^"]*"|\S+)/, "")
      .trim();
    node.meta = meta.length ? meta : null;
  }
  if (Array.isArray(node.children)) {
    node.children.forEach(transform);
  }
}

module.exports = function remarkIncludeCode() {
  return (tree) => {
    transform(tree);
  };
};
