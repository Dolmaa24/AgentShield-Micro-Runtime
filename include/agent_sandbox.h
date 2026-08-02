/* AgentShield micro-runtime — judge an agent's shell command before it runs.
 *
 * Link against libshellguard.dylib / libshellguard.so, or the static library.
 * The header is named for the project; the library and its `sg_` symbols are
 * named for the component inside it. The two refer to the same thing.
 *
 * Threading
 * ---------
 * An sg_gate is immutable and may be shared by any number of threads. An
 * sg_worker holds the caches and scratch buffers that make evaluation fast and
 * must not be shared: give each thread its own. This is deliberate — hiding a
 * mutex inside the gate would put lock contention on the hot path of the thing
 * whose entire selling point is its latency.
 *
 * Memory
 * ------
 * Every pointer returned by sg_decision_* is owned by the sg_decision and is
 * valid until sg_decision_free. Copy anything you need to keep.
 *
 * Errors
 * ------
 * sg_evaluate never returns NULL for an ordinary bad command — an unparseable
 * or oversized command is a *decision* (SG_DENY), not an error. NULL means the
 * arguments themselves were unusable.
 */

#ifndef AGENT_SANDBOX_H
#define AGENT_SANDBOX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Verdicts, ordered by severity. */
#define SG_ALLOW   0  /* run it directly                     */
#define SG_CONFINE 1  /* run it inside the sandbox           */
#define SG_ASK     2  /* escalate to a human                 */
#define SG_DENY    3  /* refuse                              */

typedef struct sg_gate sg_gate;
typedef struct sg_worker sg_worker;
typedef struct sg_decision sg_decision;

/* Create a gate.
 *
 * workspace   directory the agent may write to; must not be NULL
 * policy_path a policy file, or NULL for the built-in ruleset
 * deadline_ms evaluation budget; 0 means the default of 10 ms
 * err_out     on failure, receives an owned message for sg_string_free
 *
 * Returns NULL on failure. */
sg_gate *sg_gate_new(const char *workspace, const char *policy_path,
                     uint64_t deadline_ms, char **err_out);
void sg_gate_free(sg_gate *gate);

/* Per-thread evaluation state. Not thread-safe; one per thread. */
sg_worker *sg_worker_new(void);
void sg_worker_free(sg_worker *worker);

/* Drop cached path resolutions. Call after anything that could change what a
 * program name resolves to — a $PATH change, or an install into a directory on
 * it — since the cache cannot notice that by itself. */
void sg_worker_invalidate_cache(sg_worker *worker);

/* Judge one command. Returns NULL only if an argument was unusable. */
sg_decision *sg_evaluate(const sg_gate *gate, sg_worker *worker,
                         const char *command);
void sg_decision_free(sg_decision *decision);

int32_t sg_decision_verdict(const sg_decision *decision);
uint64_t sg_decision_elapsed_ns(const sg_decision *decision);

/* Non-zero if evaluation ran to completion. Zero means the command did not
 * parse, the deadline expired, or a wrapper chain was too deep — in which case
 * the verdict is the configured fail-closed one and is never SG_ALLOW. */
int32_t sg_decision_complete(const sg_decision *decision);

/* The full decision as JSON: verdict, capabilities, and every finding with its
 * rule id, reason, excerpt and byte span. */
const char *sg_decision_json(const sg_decision *decision);

size_t sg_decision_finding_count(const sg_decision *decision);
/* NULL if index is out of range. */
const char *sg_decision_finding_rule(const sg_decision *decision, size_t index);
const char *sg_decision_finding_reason(const sg_decision *decision, size_t index);

/* ---------------------------------------------------------------- engine
 *
 * The gate answers "should this run". The engine answers "run it, and put the
 * workspace back if it goes wrong". Both are exposed because they are
 * different questions: a harness may want to judge a command, show the reason
 * to a model, and never execute it.
 *
 * Engine results cross as JSON. The shape is already an interface the CLI
 * publishes, one serialiser is easier to keep honest than two, and a caller in
 * Python or Node has a JSON parser to hand while it does not have a C struct
 * layout.
 */

typedef struct sg_engine sg_engine;

/* Create an engine rooted at a workspace.
 *
 * workspace  the directory the agent may write to; must not be NULL
 * protected  NULL, or newline-separated paths that must not change
 * timeout_ms per-command execution budget; 0 for the default
 * flags      SG_* below, OR-ed together
 * err_out    on failure, receives an owned message for sg_string_free
 *
 * Returns NULL on failure. */

/* Roll back when the command exits non-zero. Off by default: a failing command
 * is not by itself a reason to discard the work it did. */
#define SG_ROLLBACK_ON_FAILURE 1u

/* Run commands the gate escalates instead of stopping at them. Off by default;
 * SG_ASK means a human should look, and running those anyway replaces a
 * decision with a default. */
#define SG_RUN_ON_ASK 2u

sg_engine *sg_engine_new(const char *workspace, const char *protected_paths,
                         uint64_t timeout_ms, uint32_t flags, char **err_out);
void sg_engine_free(sg_engine *engine);

/* The runtime backend in use: "local", "vz", "firecracker", "gvisor". */
const char *sg_engine_runtime(const sg_engine *engine);

/* Judge a command without running it. Returns owned JSON for sg_string_free,
 * or NULL if an argument was unusable. */
char *sg_engine_eval_json(const sg_engine *engine, const char *command);

/* Gate, checkpoint, execute, verify, roll back. Returns owned JSON for
 * sg_string_free, or NULL if an argument was unusable.
 *
 * A command the gate refuses does not run, and that is reported in the JSON as
 * "ran": false rather than as an error — refusing is a successful outcome of
 * the call, not a failure of it.
 *
 * Not safe to call concurrently on one engine from several threads. */
char *sg_engine_execute_json(const sg_engine *engine, const char *command);

const char *sg_version(void);
/* The confinement backend on this platform: "seatbelt", "landlock+seccomp",
 * or "none". */
const char *sg_backend(void);

/* Free a string handed back through an out-parameter. */
void sg_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* AGENT_SANDBOX_H */
