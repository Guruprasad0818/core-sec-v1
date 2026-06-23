# CBAD Stage 4 — Semantic SAST Platform

## SECTION 1 — Taint Tracking Theory & Definition Specs

### 1.1 Overview

Stage 4 defines an enterprise-grade semantic SAST platform focused on taint tracking and data-flow analysis. The platform performs deep code analysis to detect security vulnerabilities by modeling how untrusted input propagates through code and reaches sensitive operations.

This section specifies the core theory and architectural definitions for data-flow taint tracking, with explicit definitions for sources, sinks, sanitizers, and the mechanics of complex interprocedural, cross-file, and cross-service analysis.

### 1.2 Taint tracking architecture

The platform architecture is built around a semantic analysis engine with these components:
- `AST / IR extractor`: converts source code into language-specific abstract syntax trees or intermediate representation
- `call graph builder`: constructs interprocedural call graphs, including dynamic dispatch resolution and reflection heuristics
- `taint propagation engine`: models taint flow across assignments, expressions, function calls, returns, fields, and containers
- `source/sink/sanitizer database`: registry of security-sensitive language/library constructs
- `path enumerator`: materializes taint paths and cross-file/cross-service propagation graphs
- `query engine`: evaluates taint rules, path constraints, and vulnerability patterns
- `reporting and prioritization`: ranks findings based on exploitability and confidence

### 1.3 Data-flow taint tracking principles

Taint tracking is based on three core concepts:
- `source`: an origin of untrusted data
- `sink`: a sensitive operation that should not receive tainted data
- `sanitizer`: a function or construct that removes or neutralizes taint

The analysis must support both `forward flow` (source -> sink) and `backward flow` (sink query for possible sources), with a preference for forward taint propagation for runtime-like semantics.

#### 1.3.1 Forward taint propagation

- initial taint labels are assigned to source expressions
- taint labels propagate through assignments, parameter passing, returns, field stores, array indexing, and container operations
- taint merges at control-flow join points, collection elements, and when multiple sources contribute
- taint loses its strength only when a sanitizer is applied or explicit sanitization conditions are met

#### 1.3.2 Backward taint analysis

- sink-centric analysis traces backwards from sink arguments to determine if a source can reach the sink
- useful for rule discovery and generating exploitability conditions
- supports `query-driven` analysis where sinks define the taint patterns to look for

#### 1.3.3 Path sensitivity and context sensitivity

- `path-sensitive`: the analysis distinguishes alternate control-flow paths and conditions, preserving taint only along feasible paths
- `context-sensitive`: the analysis distinguishes function call sites by call stack or calling context to avoid imprecise merging
- support `k-CFA` or `object-sensitive` analysis for object-oriented languages and dynamic dispatch

### 1.4 Source definitions

Sources define untrusted or potentially attacker-controlled data.

#### 1.4.1 General source taxonomy

- `HTTP request input`: query parameters, POST bodies, headers, cookies
- `environment variables` and system properties
- `configuration files` loaded at runtime
- `file input` from disk, network, or upload locations
- `database inputs` retrieved from external queries
- `message queue payloads` and broker messages
- `inter-service request payloads`
- `command-line arguments`
- `deserialization inputs`
- `external API responses`

#### 1.4.2 Source definition schema

Each source is defined by a rule with:
- `language`
- `module/library`
- `code pattern`
- `return type`
- `taint label`
- `source tags` e.g. `user-controlled`, `network`, `filesystem`, `metadata`

Example schema:
```yaml
source:
  name: http_request_query_param
  language: java
  pattern: HttpServletRequest.getParameter(*)
  taint_label: user_input
  tags: [user-controlled, http]
```

#### 1.4.3 Source classification

Sources may be classified by trust level:
- `untrusted`: direct request parameters, raw body bytes
- `semi-trusted`: internal service payloads with authorization metadata
- `trusted`: configuration values and compile-time constants

The engine uses classification to refine sink sensitivity and sanitizer strength.

#### 1.4.4 Example source definitions

- Spring Boot: `HttpServletRequest.getParameter`, `@RequestBody`, `@PathVariable`, `ServletRequest.getHeader`
- Node.js: `req.params`, `req.query`, `req.body`, `process.env`, `child_process.execFile` inputs
- Python: `request.args.get`, `request.json`, `os.environ.get`, `sys.argv`

### 1.5 Sink definitions

Sinks represent security-sensitive operations where tainted data may cause exploitation.

#### 1.5.1 General sink taxonomy

- `command execution`
- `SQL execution`
- `OS command invocation`
- `LDAP query`
- `XPath/XQuery evaluation`
- `template rendering`
- `HTML generation` and DOM insertion
- `shell invocation`
- `deserialization`
- `file system path creation`
- `network requests`
- `authentication/authorization bypass`
- `log injection`
- `OS path traversal`

#### 1.5.2 Sink definition schema

Each sink rule includes:
- `language`
- `module/library`
- `code pattern`
- `argument positions` to inspect
- `sink tags` e.g. `sql`, `command`, `xss`, `ssrf`
- `severity`
- `description`

Example schema:
```yaml
sink:
  name: jdbc_execute_query
  language: java
  pattern: java.sql.Statement.executeQuery(*)
  arg_positions: [0]
  tags: [sql_injection]
  severity: high
```

#### 1.5.3 Sink classification

Sinks may be classified by exploitation cost:
- `critical`: direct command or SQL execution, remote file inclusion
- `high`: injection into templates or dynamic code eval
- `medium`: log injection or path traversal if exploitable
- `low`: code patterns requiring additional preconditions

#### 1.5.4 Example sink definitions

- Spring Boot: `JdbcTemplate.query`, `PreparedStatement.execute`, `Runtime.getRuntime().exec`, `TemplateEngine.process`
- Node.js: `child_process.exec`, `fs.writeFile`, `vm.runInNewContext`, `eval`, `db.query`
- Python: `subprocess.Popen`, `os.system`, `cursor.execute`, `yaml.load`, `jinja2.Template.render`

### 1.6 Sanitizer definitions

Sanitizers are constructs that neutralize or validate tainted data before reaching a sink.

#### 1.6.1 Sanitizer taxonomy

- `escapers`: HTML escape, SQL escape, shell escape
- `validators`: input validation, regex validation, type coercion
- `encoders`: URL encoding, base64 encoding
- `binders`: prepared statements, parameterized query builders
- `normalizers`: canonicalization, path normalization
- `sanitization libraries`: OWASP ESAPI, Apache Commons Text, parameterized ORM methods

#### 1.6.2 Sanitizer schema

Each sanitizer rule includes:
- `language`
- `module/library`
- `pattern`
- `sanitizer type`
- `applicable sinks`
- `effect`: `neutralize`, `validate`, `encode`, `reject`
- `confidence`

Example schema:
```yaml
sanitizer:
  name: prepared_statement_parameter
  language: java
  pattern: PreparedStatement.setString(*, *)
  sanitizer_type: parameterized_query
  applicable_sinks: [jdbc_execute_query]
  effect: neutralize
```

#### 1.6.3 Sanitizer strength and taint weakening

Sanitizers can have different strength levels:
- `strong`: fully neutralizes taint for compatible sinks
- `conditional`: requires specific sink usage and may only reduce taint
- `weak`: only partial sanitization, leaving residual risk

The taint engine models sanitizer application by:
- removing taint from sanitized expressions when semantics are strong and sink-compatible
- tagging sanitized values with `residual taint` if sanitization is partial or context-specific
- preserving `taint context` for later validation if sanitizer use is incomplete

#### 1.6.4 Example sanitizer definitions

- Spring Boot: `JdbcTemplate.query(String, Object[])`, `PreparedStatement.setString`, `HtmlUtils.htmlEscape`
- Node.js: `mysql.escape`, `pg.format`, `encodeURIComponent`, `validator.isInt`
- Python: `psycopg2.sql.SQL()`, `jinja2.escape`, `urllib.parse.quote_plus`, `re.fullmatch`

### 1.7 Complex interprocedural analysis

#### 1.7.1 Interprocedural taint propagation

- track taint across function boundaries:
  - parameter taint enters callee scopes
  - return values carry taint back to caller
  - global and static fields propagate taint across functions
- use `call graph analysis` to identify call targets, including virtual dispatch and interface implementations
- apply `context sensitivity` to distinguish taint flow in different call sites
- support `recursive` and `mutually recursive` functions with fixpoint iteration until taint stabilization

#### 1.7.2 Cross-file analysis

- build a project-wide symbol table and module import graph
- analyze imported functions, classes, and variables across file boundaries
- resolve aliasing from imports (`import x as y`, `const z = require('x')`, `from x import y`)
- propagate taint through exported and imported bindings
- handle dynamic import patterns and module path resolution heuristics

#### 1.7.3 Cross-service analysis

- model service boundaries via explicit serialization and network communication constructs
- identify inter-service sources and sinks:
  - incoming service requests become sources in the receiving service
  - outgoing HTTP client payloads may carry taint from the sender
- build a `service graph` where taint flows across RPC, REST, messaging, and gRPC boundaries
- support taint propagation across message queues, event buses, and API contracts by modeling:
  - `serialize/deserialize` transforms
  - request/response payload mapping
  - protocol-level field mappings

#### 1.7.4 Polymorphism and dynamic dispatch

- resolve method call targets using class hierarchy, interface binding, and type inference
- use `points-to analysis` for dynamically typed languages to approximate object types
- apply `method summary` caching for frequently called polymorphic targets

#### 1.7.5 Container and collection modeling

- model taint propagation through arrays, lists, maps, sets, and objects
- preserve taint for container elements and fields when the container is assigned or passed
- track `taint index` for element-level access when the index/key is derived from tainted data
- support deep container flows for nested structures such as JSON objects

#### 1.7.6 Path feasibility and conditional logic

- incorporate branch conditions into taint propagation
- prune taint paths that are infeasible based on simple constraint solving
- model sanitization conditions that depend on predicates (e.g. `if (isSafe(input))`)
- support `taint predicates` for validation-based sanitizers and manual checks

### 1.8 Taint path materialization and reporting

- materialize end-to-end taint paths from sources to sinks
- attach source location, sanitized expressions, and sink metadata
- compute path severity based on sink risk, source trust, and sanitizer strength
- support finding suppression if a valid sanitizer is proven along all taint paths
- provide detailed path reports for triage, including cross-file/service edges and call stack

### 1.9 Example taint propagation mechanics

Example Java path:
- `HttpServletRequest.getParameter("id")` is tainted as `user_input`
- passed into `service.process(input)`
- stored in `this.userInput`
- later used in `jdbcTemplate.query("SELECT * FROM users WHERE id=" + this.userInput)`
- if no sanitizer exists, the path is reported as SQL injection risk

Example Node.js path:
- `req.query.name` tainted
- assigned to `const username = req.query.name`
- passed into `db.query('SELECT * FROM users WHERE name = ' + username)`
- path reported with dynamic string concatenation sink

Example Python path:
- `request.args.get('file')` tainted
- passed to `open(os.path.join(base_dir, filename))`
- path reported as path traversal risk if `filename` is unsanitized

## SECTION 2 — Multi-Language Support Rules

### 2.1 Overview

The semantic SAST platform must support multi-language taint tracking with explicit injection vector rules for Spring Boot (Java), Node.js (JavaScript/TypeScript), and Python. This section defines language-specific rule frameworks for sources, sinks, and sanitizers.

### 2.2 Spring Boot (Java) rules

#### 2.2.1 Source vectors

- `HttpServletRequest.getParameter(*)`
- `HttpServletRequest.getHeader(*)`
- `HttpServletRequest.getCookies()` / `Cookie.getValue()`
- `@RequestBody` annotated controller parameters
- `@RequestParam` and `@PathVariable`
- `ServletRequest.getInputStream()` and `getReader()`
- `SecurityContextHolder.getContext().getAuthentication().getPrincipal()` when principal contains user-controlled fields
- `MultipartFile.getBytes()` and `getInputStream()`
- `@ModelAttribute` bound fields from request data
- `Environment.getProperty(*)` and `System.getenv(*)`

#### 2.2.2 Sink vectors

- JDBC and JPA execution:
  - `JdbcTemplate.query(*)`, `update(*)`, `execute(*)`
  - `Statement.executeQuery(*)`, `executeUpdate(*)`
  - `EntityManager.createQuery(*)`, `createNativeQuery(*)`
- command execution:
  - `Runtime.getRuntime().exec(*)`
  - `ProcessBuilder.start()`
- templating and view rendering:
  - `thymeleafTemplateEngine.process(*)`
  - `StringTemplateLoader`, `ModelAndView` templates with unsanitized model attributes
- file system operations:
  - `new File(input)`
  - `Files.write(*)`, `FileOutputStream` with tainted paths
- XML/XPath evaluation:
  - `XPath.evaluate(*)`
  - `DocumentBuilder.parse(*)` with tainted file or URL
- expression evaluation:
  - `ScriptEngine.eval(*)`
- log injection:
  - `logger.info(*)`, `logger.error(*)` with tainted message content
- SSF or template injection in JSP/Thymeleaf fragments

#### 2.2.3 Sanitizer vectors

- prepared statement APIs:
  - `PreparedStatement.setString`, `setInt`, `setObject`
  - `NamedParameterJdbcTemplate.update(*)`
- escaping and encoding:
  - `StringEscapeUtils.escapeHtml4(*)`
  - `HtmlUtils.htmlEscape(*)`
  - `URLEncoder.encode(*)`
  - `StringEscapeUtils.escapeSql(*)`
- validation:
  - `Pattern.matches(*)`
  - `Integer.parseInt(*)` with explicit range checks
  - `@Valid`, `@Validated` bean validation on DTOs
- path normalization:
  - `Paths.get(baseDir).resolve(userInput).normalize()`
- deserialization validation:
  - `ObjectMapper.readValue(*)` with safe typing and allowed class filters

#### 2.2.4 Injection vector rules

- SQL injection: string concatenation into JDBC or JPA query strings
- command injection: tainted arguments in `Runtime.exec` or `ProcessBuilder`
- XSS: tainted request parameters in rendered templates or response bodies
- SSRF: tainted URLs used in `RestTemplate.getForObject` or `WebClient` calls
- file path traversal: unvalidated path segments in file APIs
- deserialization: tainted serialized payloads passed to `ObjectMapper.readValue`

### 2.3 Node.js (JavaScript/TypeScript) rules

#### 2.3.1 Source vectors

- Express/Koa request inputs:
  - `req.query.*`, `req.params.*`, `req.body.*`, `req.headers.*`, `req.cookies.*`
  - `ctx.request.body`, `ctx.params`, `ctx.query`
- raw HTTP request streams:
  - `req.on('data')`, `req.socket` data reads
- environment and CLI inputs:
  - `process.env.*`, `process.argv[*]`
- file system inputs:
  - `fs.readFileSync`, `fs.createReadStream`
- external message payloads:
  - `amqp.message.content`, `kafkaMessage.value`
- WebSocket messages and socket input

#### 2.3.2 Sink vectors

- SQL/database sinks:
  - `client.query(queryString)`
  - `sequelize.query(*)`
  - `mongoose.Model.find(*)` with raw filter objects
  - `mongoClient.db().command(*)`
- command execution:
  - `child_process.exec`, `execSync`, `spawn`, `spawnSync`, `fork`
  - `shelljs.exec`
- template engines:
  - `ejs.render(*)`, `pug.renderFile(*)`, `handlebars.compile(*)`
- eval and dynamic code:
  - `eval(*)`, `new Function(*)`, `vm.runInThisContext(*)`
- file path and OS APIs:
  - `fs.writeFileSync(path, *)`, `path.resolve(userInput)`
  - `fs.createWriteStream(userInput)`
- SSRF and HTTP clients:
  - `axios.get(url)`, `request(url)`, `fetch(url)`
- XML/XPath:
  - `xml2js.Parser().parseString(*)`, `xpath.select(*)`
- log injection:
  - `console.log(*)`, `logger.info(*)`

#### 2.3.3 Sanitizer vectors

- escaping libraries:
  - `mysql.escape`, `mysql.format`
  - `pg.Client.query({ text, values })`
  - `xss` library sanitization
- validation libraries:
  - `validator.isInt`, `validator.isAlphanumeric`, `joi.validate`
  - `express-validator` middleware
- encoding:
  - `encodeURIComponent`, `encodeURI`, `querystring.escape`
- parameterized APIs:
  - `knex('table').where('id', userInput)`
  - `sequelize.where` parameter binding
  - `pg` parameter array queries
- path normalization:
  - `path.normalize(path.join(baseDir, userInput))`
- safe templating:
  - `handlebars.SafeString` sanitization

#### 2.3.4 Injection vector rules

- SQL injection: dynamic query string construction using template literals or concatenation
- command injection: untrusted values passed to shell command arguments or interpolated shell strings
- XSS: request data used in template rendering without escaping
- SSRF: tainted URLs used in outbound HTTP client calls
- path traversal: unvalidated path segments in `path.join`/`fs` APIs
- insecure deserialization: `JSON.parse` or `eval` on untrusted input when object shape is not validated

### 2.4 Python rules

#### 2.4.1 Source vectors

- web framework inputs:
  - Flask: `request.args.get`, `request.form.get`, `request.data`, `request.get_json()`
  - Django: `request.GET`, `request.POST`, `request.body`, `request.FILES`
- environment and CLI:
  - `os.environ.get`, `sys.argv[*]`
- file and network inputs:
  - `open()`, `Path.read_text()`, `socket.recv()`
- message queue inputs:
  - `json.loads(message.body)`, `payload = message.value`
- deserialization inputs:
  - `pickle.loads`, `yaml.safe_load` on untrusted content

#### 2.4.2 Sink vectors

- database execution:
  - `cursor.execute(query, params)` with templated query strings
  - `session.execute(text(query))` in SQLAlchemy
- command execution:
  - `subprocess.Popen`, `subprocess.run`, `os.system`
- template rendering:
  - `jinja2.Template.render`, `render_to_string`, `flask.render_template`
- file path APIs:
  - `open(user_path)`, `Path(user_path)`
- eval/dynamic execution:
  - `eval(*)`, `exec(*)`, `compile(*)`
- XML/XPath:
  - `lxml.etree.parse(*)`, `xml.etree.ElementTree.fromstring(*)`
- HTTP clients:
  - `requests.get(url)`, `urllib.request.urlopen(url)`
- log injection:
  - `logging.info(msg)`, `logger.warning(msg)` with untrusted text

#### 2.4.3 Sanitizer vectors

- database parameterization:
  - `cursor.execute(query, params)`, `engine.execute(text(query), **params)`
- escaping:
  - `html.escape`, `urllib.parse.quote_plus`, `xml.sax.saxutils.escape`
- validation:
  - `re.fullmatch`, `schema.Schema`, `pydantic` models
- safe templating:
  - `jinja2.escape`, built-in autoescape mode in Flask/Jinja
- path normalization:
  - `os.path.normpath(os.path.join(base_dir, user_path))`
- secure deserialization:
  - `json.loads` with schema validation, `yaml.safe_load`

#### 2.4.4 Injection vector rules

- SQL injection: string interpolation in query commands or ORM `text()` calls
- command injection: tainted values in shell commands or `subprocess` calls
- XSS: tainted data rendered into web templates without escaping
- SSRF: tainted URL arguments in outbound HTTP requests
- path traversal: tainted file path arguments passed to filesystem APIs
- insecure deserialization: untrusted payloads passed to `pickle.loads`, `yaml.load`

### 2.5 Cross-language rule framework

#### 2.5.1 Common rule meta-model

The multi-language rule framework uses a common meta-model with fields:
- `rule_id`
- `language`
- `category`
- `source_pattern`
- `sink_pattern`
- `sanitizer_pattern`
- `tags`
- `severity`
- `confidence`
- `description`
- `examples`

#### 2.5.2 Language-specific rule translation

- map generic taint concepts to language constructs via language-specific adapters
- normalize abstractions such as `http request`, `sql query`, `command execution`
- support language-specific expression matching and type resolution
- store rule bindings for each supported runtime library and framework version

#### 2.5.3 Multi-language analysis engine

- use a common taint propagation core with pluggable language frontends
- each frontend provides:
  - AST/IR extraction
  - call graph construction and type information
  - source/sink/sanitizer rule matching
  - module/import resolution
- the core unifies taint semantics and reports findings in a normalized format

### 2.6 Reporting high-fidelity findings

- each finding includes source location, sink location, taint path, sanitizer evidence, and confidence score
- group findings by vulnerability class and triage priority
- provide actionable remediation hints, e.g. use parameterized queries or proper escaping
- make cross-file and cross-service paths explicit in the report graph

### 2.7 Summary

This Stage 4 design establishes a robust data-flow taint tracking foundation for an enterprise semantic SAST platform. It includes detailed theory, source/sink/sanitizer definitions, complex interprocedural semantics, and multi-language rules for Spring Boot, Node.js, and Python.

## SECTION 3 — CodeQL & Semgrep Library Integration

### 3.1 Integration strategy

The platform should incorporate both CodeQL and Semgrep as complementary rule engines. CodeQL provides semantic control/data-flow analysis at scale for Java and Python, while Semgrep provides fast structural pattern detection across Java, JavaScript/TypeScript, and Python.

- Use CodeQL for deep interprocedural taint query coverage and path-sensitive findings
- Use Semgrep for quick library-based pattern matching and custom rule distribution
- Normalize alerts from both engines into a shared internal schema with:
  - `rule_id`
  - `tool`
  - `language`
  - `finding_type`
  - `source`
  - `sink`
  - `path`
  - `confidence`
  - `fix_suggestion`

### 3.2 Production-grade CodeQL query example

This CodeQL query flags unsanitized user input flowing from a Spring Boot controller endpoint into raw SQL execution or a command invocation.

```ql
import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.Sanitizer

class ControllerSource extends DataFlow::SourceNode {
  ControllerSource() {
    exists(MethodAccess ma | ma.getMethod().getName() = "getParameter" and ma.getReceiver().getType().hasQualifiedName("javax.servlet.http", "HttpServletRequest"))
  }
}

class RawSqlSink extends DataFlow::SinkNode {
  RawSqlSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "executeQuery" and
      ma.getReceiver().getType().hasQualifiedName("java.sql", "Statement")
    )
  }
}

class CommandExecutionSink extends DataFlow::SinkNode {
  CommandExecutionSink() {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "exec" and
      ma.getReceiver().getType().hasQualifiedName("java.lang", "Runtime")
    )
  }
}

class SqlSanitizer extends Sanitizer {
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "setString" and
      ma.getReceiver().getType().hasQualifiedName("java.sql", "PreparedStatement")
    )
  }
}

class CommandSanitizer extends Sanitizer {
  override predicate isSanitizer(DataFlow::Node node) {
    exists(MethodAccess ma |
      ma.getMethod().getName() = "escapeArgument" and
      ma.getReceiver().getType().hasQualifiedName("org.apache.commons.text", "StringEscapeUtils")
    )
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, DataFlow::Path path
where
  source = ControllerSource() and
  sink = RawSqlSink() and
  DataFlow::localFlows(source, sink, path, [SqlSanitizer])
select source, sink, path, "Unsanitized controller input flows into raw SQL execution."
```

### 3.3 Production-grade Semgrep rule example

This Semgrep rule targets Spring Boot-style controller input used directly in string-concatenated SQL or shell command sinks.

```yaml
rules:
  - id: cbad-java-raw-sql-command-taint
    languages: [java]
    message: "Unsanitized controller input flows directly into raw SQL or command execution."
    severity: ERROR
    metadata:
      category: security
      cwe: 89
      confidence: medium
    patterns:
      - pattern-either:
          - pattern: |
              $REQUEST.getParameter($PARAM)
              ...
              $SQL.executeQuery($QUERY)
          - pattern: |
              $REQUEST.getParameter($PARAM)
              ...
              Runtime.getRuntime().exec($CMD)
    languages:
      - java
    message: |
      Controller-sourced request data is used in raw SQL execution or OS command execution without sanitization.
    metadata:
      technology: spring-boot
      rule-type: taint-flow
    severity: ERROR
    languages: [java]
    patterns:
      - pattern-inside: |
          class $Class {
            ...
            public $ReturnType $Method($Type $request) {
              ...
              $REQUEST.getParameter($PARAM)
              ...
              $SINK
            }
          }
    pattern-either:
      - pattern: $SINK.executeQuery($QUERY)
      - pattern: Runtime.getRuntime().exec($CMD)
    message: "Unsanitized controller input may reach SQL or command execution."
    fix: |
      // Use parameterized queries or sanitize shell arguments
      PreparedStatement ps = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
      ps.setString(1, $PARAM);
      ps.executeQuery();
```

### 3.4 Toolchain implementation notes

- run CodeQL batch queries in CI for Java/Python and ingest `.sarif` output
- run Semgrep as a lightweight pre-commit and PR gate for Java/JS/Python patterns
- correlate CodeQL and Semgrep findings by normalized code location and rule metadata
- retain raw code snippets and AST node identifiers to support downstream AI verification

## SECTION 4 — AI-Based False Positive Reduction

### 4.1 Design goals

The AI verification layer must reduce noise, validate exploitability, and generate auto-fix recommendations with minimal human intervention.

Goals:
- ingest raw SAST alerts from CodeQL, Semgrep, and the internal taint engine
- enrich each finding with full function and method context
- apply LLM reasoning against explicit validation criteria rather than free-form heuristics
- suppress low-confidence false positives and surface high-fidelity triage-ready alerts
- generate code-level remediation suggestions and safe examples

### 4.2 Claude API wrapper architecture

The wrapper provides a deterministic interface for context expansion, prompt templating, and validation policy enforcement.

Components:
- `alert normalizer`: converts tool output to a shared schema
- `context extractor`: collects surrounding function, file, and call chain source code
- `prompt builder`: builds structured prompts with explicit facts and validation questions
- `Claude client`: sends requests to Claude API with max tokens, temperature control, and traceable request IDs
- `response parser`: extracts decision flags, confidence scores, and remediation suggestions
- `verification policy engine`: applies hard rules to override or filter model output

### 4.3 Validation criteria and suppression rules

The model uses explicit criteria for verification. If any criterion fails, the alert is suppressed or downgraded.

Validation criteria:
- `source authenticity`: confirm the flow begins from a recognized untrusted source
- `sink relevance`: confirm the sink is a raw SQL or command invocation from the same function or reachable call path
- `sanitizer elimination`: confirm no sanitizer or parameterization occurs on the path
- `control-flow feasibility`: confirm the path is feasible under common execution conditions
- `context completeness`: confirm the function body and call-site contexts are available

Suppression rules:
- suppress if the path only reaches a prepared statement parameter binding or safe ORM API
- suppress if the taint originates from a trusted configuration constant
- suppress if the model is uncertain and the path shows explicit sanitization checks
- do not suppress if the sink is high-risk and there is a direct unvalidated string concatenation into SQL or command APIs

### 4.4 Prompt design for Claude

Prompts are structured into sections: `alert summary`, `code context`, `verification checklist`, and `response format`.

Example prompt outline:
- `ALERT SUMMARY`: tool, rule, source, sink, file, line
- `CODE CONTEXT`: full function/method body, caller stubs, relevant imports
- `VERIFICATION CHECKLIST`:
  1. Does the source trace from an untrusted endpoint parameter?
  2. Does the sink execute raw SQL or shell commands?
  3. Is there a sanitizer, prepared statement, or parameterized API?
  4. Is the path feasible on a normal execution path?
- `RESPONSE FORMAT`: JSON with keys `verified`, `false_positive_risk`, `suppression_reason`, `remediation`

### 4.5 Claude wrapper contract

The wrapper should implement:
- `verifyFinding(alert, codeContext) -> VerificationResult`
- `suggestFix(alert, codeContext) -> FixRecommendation`
- `evaluateBatch(alerts) -> Array<VerificationResult>`

`VerificationResult` fields:
- `findingId`
- `verified`: `true|false`
- `falsePositiveRisk`: `low|medium|high`
- `suppressionReason`: optional string
- `confidence`: numeric score
- `remediation`: optional suggested code edit

`FixRecommendation` fields:
- `ruleId`
- `filePath`
- `lineRange`
- `suggestedPatch`
- `explanation`

### 4.6 Example AI verification flow

1. CI collects CodeQL/Semgrep alerts for a PR
2. Internal normalizer converts alerts and attaches full method bodies
3. Claude wrapper sends a prompt with explicit validation questions
4. Claude returns a JSON result and recommended patch if verified
5. Policy engine suppresses alerts where `verified=false` and `falsePositiveRisk=high`
6. Verified findings are annotated in the PR with auto-fix guidance

### 4.7 Auto-fix recommendation design

Auto-fix recommendations should prioritize safe remediation patterns and avoid altering semantics.

- for raw SQL flows: recommend parameterized queries or strong ORM APIs
- for command injection flows: recommend argument arrays or sanitized wrappers
- include exact code snippets rather than abstract guidance
- tag suggestions with `fix_confidence` and `fix_type` (e.g. `parameterized_query`, `shell_argument_escape`)

### 4.8 Production hardening

- cache model decisions for repeated findings to avoid duplicate Claude calls
- use deterministic prompts and temperature=0 for reproducible verification
- log full request/response payloads securely for audit and tuning
- enforce a maximum token budget and split large contexts into prioritized segments
- validate model JSON output with schema parsing and fallback on non-model heuristics if parsing fails

### 4.9 Summary

This AI layer provides an enterprise-grade false positive reduction mechanism that combines deterministic verification criteria with Claude-powered reasoning. It enables the semantic SAST platform to suppress noise, surface actionable findings, and generate remediation recommendations for raw SQL and system command taint paths.

## SECTION 5 — IDE & CI/CD Integration at Scale

### 5.1 Architecture overview

Stage 4 must scale across a massive multi-million-line monorepo. The architecture separates interactive IDE experiences from pipeline-scale distributed scanning.

- `IDE client`: a custom VS Code extension for developers
- `analysis backend`: cloud/cluster service that executes CodeQL, Semgrep, and internal taint scans
- `scan orchestrator`: distributes jobs with file-shard assignment, dependency awareness, and incremental analysis
- `results aggregator`: normalizes findings, merges duplicates, and attaches AI verification
- `cache layer`: stores scan artifacts, AST/IR snapshots, and previous scan results for incremental reuse
- `pipeline bridge`: connects CI runner stages to the analysis backend and enforces timeouts

### 5.2 VS Code extension interface

The custom extension should provide:
- scan initiation controls for `workspace`, `project`, or `file` scope
- inline diagnostics with source/sink path details and actionable remediation hints
- `CodeLens` anchors for `go to source`, `go to sink`, and `open taint path`
- context menu commands for `verify with AI`, `suppress finding`, and `request fix suggestion`
- a dedicated panel showing `current findings`, `scan status`, `last verified`, and `active rules`

#### 5.2.1 IDE workflow

1. developer opens monorepo and activates the extension
2. extension syncs workspace metadata and language configuration
3. extension requests incremental scan for edited files from the backend
4. backend returns diagnostics and suggested fixes
5. developer reviews inline results and optionally invokes `Claude verification` on a finding

#### 5.2.2 Extension architecture

- `frontend`: VS Code extension UI and editor decorations
- `language adapters`: file-type handlers for Java, JavaScript/TypeScript, Python
- `backend connector`: REST/WebSocket link to the analysis backend
- `local cache`: caches recent scan results for interactive performance
- `telemetry sink`: anonymized usage metrics and scan latency data

### 5.3 CI/CD runner execution loops

CI must run distributed scans without hitting pipeline timeouts. The pipeline logic is designed for multi-stage execution with parallel shards and incremental work.

#### 5.3.1 Runner stages

- `stage 1 — discovery`: compute touched files, dependency boundaries, and shard groups
- `stage 2 — pre-filter`: select active language targets and determine incremental scan eligibility
- `stage 3 — shard execution`: dispatch scanners to worker nodes with explicit file sets
- `stage 4 — aggregation`: gather raw findings, deduplicate, and normalize
- `stage 5 — AI verification`: invoke Claude-based reduction and attach auto-fix suggestions
- `stage 6 — publish`: emit SARIF, IDE diagnostics, and PR annotations

#### 5.3.2 Execution loop design

- use a `fan-out/fan-in` model to parallelize by package, language, and repository zone
- execute lightweight Semgrep rules early for quick feedback
- run deep CodeQL/taint scans on high-risk shards and changed modules
- keep each shard under a configurable execution budget (for example, 15–30 minutes per shard)
- implement `watchdog` monitoring to restart or reroute stalled shards

### 5.4 Sharding and distributed scanning

The system must partition a monorepo intelligently to maximize parallelism and preserve precision.

#### 5.4.1 Shard design patterns

- `file-based sharding`: divide files by module, package, or language area
- `semantic shards`: divide by dependency graph clusters and strongly connected component boundaries
- `credential domains`: separate client-facing code, backend services, and shared libraries into different scan sets
- `incremental shards`: run only changed files plus impacted dependency closure

#### 5.4.2 Dependency-aware scan grouping

- build a language-aware dependency graph for imports, package references, and service contracts
- assign related files to the same shard when taint propagation or data flow can cross them
- avoid false negatives by grouping modules that share critical call graph edges
- use `impact analysis` to expand a changed file set into the minimal closure needing re-scan

#### 5.4.3 Distributed scan orchestration

- `scheduler`: assigns shards to worker nodes based on CPU, memory, and tool affinity
- `worker`: executes one or more CodeQL/Semgrep/taint tasks for its assigned shard
- `artifact store`: persists intermediate AST/IR, preprocessed rulematcher outputs, and scan logs
- `checkpointing`: record shard progress and allow resuming from partial results
- `retry policy`: automatically retry transient failures and reroute overloaded workers

#### 5.4.4 Timeout mitigation

- use `progressive scan depth` for larger shards: quick symptomatic scan first, deep scan second
- cap runtime at shard-level and fallback to best-effort analysis if a hard deadline approaches
- cache and reuse results from unchanged dependencies to reduce repeat work
- split oversized shard candidates until per-worker runtime is predictable

### 5.5 Scale-safe reporting and feedback

- merge duplicate findings across shards using normalized source/sink location and path similarity
- preserve provenance with shard identifiers, tool source, and AI verification status
- publish results as:
  - SARIF for downstream ingestion
  - VS Code diagnostics via the extension
  - PR comments/annotations with priority and remediation guidance
- support `issue bundling` to reduce noise in monorepo-wide reports by grouping related taint paths

### 5.6 Enterprise governance

- support role-based gating so operations teams can require `QA approval` for high-risk findings
- integrate with existing monorepo build farms and runner pools
- enforce `scan policy templates` for different repository zones (frontend, backend, infra, shared libs)
- provide dashboards for scan throughput, average latency, and verification suppression rates

### 5.7 Summary

Section 5 completes Stage 4 with enterprise-grade IDE and CI/CD integration design. It defines a distributed scanning blueprint for monorepos, a custom VS Code extension experience, shard-aware CI loops, and timeout-safe orchestration so the SAST platform scales to multi-million LOC repositories.
