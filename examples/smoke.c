/* A C caller, which is the realistic shape of an integration: an agent
 * harness that has just had a model produce a command and needs an answer
 * before running it.
 *
 * Build and run:
 *   cargo build --release -p shellguard-ffi
 *   cc -Iinclude examples/smoke.c -Ltarget/release -lshellguard -o /tmp/smoke
 *   /tmp/smoke
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "agent_sandbox.h"

static const char *verdict_name(int32_t v) {
    switch (v) {
    case SG_ALLOW:   return "allow";
    case SG_CONFINE: return "confine";
    case SG_ASK:     return "ask";
    case SG_DENY:    return "deny";
    default:         return "?";
    }
}

int main(void) {
    char *err = NULL;
    sg_gate *gate = sg_gate_new("/tmp", NULL, 0, &err);
    if (!gate) {
        fprintf(stderr, "sg_gate_new: %s\n", err ? err : "unknown");
        sg_string_free(err);
        return 1;
    }

    sg_worker *worker = sg_worker_new();
    if (!worker) {
        fprintf(stderr, "sg_worker_new failed\n");
        sg_gate_free(gate);
        return 1;
    }

    printf("shellguard %s, %s backend\n\n", sg_version(), sg_backend());

    struct { const char *cmd; int32_t want; } cases[] = {
        { "git status",                          SG_ALLOW   },
        { "cargo build",                         SG_CONFINE },
        { "git push --force origin main",        SG_ASK     },
        { "rm -rf /etc",                         SG_DENY    },
        /* The same delete wearing three other programs' names. */
        { "sudo timeout 5 rm -rf /etc",          SG_DENY    },
        { "find . -exec rm -rf /etc {} \\;",     SG_DENY    },
        { "bash -c 'rm -rf /etc'",               SG_DENY    },
        /* Unparseable input is a decision, not an error. */
        { "echo $(unterminated",                 SG_DENY    },
    };

    int failures = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        sg_decision *d = sg_evaluate(gate, worker, cases[i].cmd);
        if (!d) {
            fprintf(stderr, "sg_evaluate returned NULL for %s\n", cases[i].cmd);
            failures++;
            continue;
        }

        int32_t got = sg_decision_verdict(d);
        int ok = (got == cases[i].want);
        if (!ok) failures++;

        printf("%-7s %s %-38s  %6.1f us\n",
               verdict_name(got),
               ok ? " " : "!",
               cases[i].cmd,
               (double)sg_decision_elapsed_ns(d) / 1000.0);

        if (sg_decision_finding_count(d) > 0) {
            printf("        %s: %s\n",
                   sg_decision_finding_rule(d, 0),
                   sg_decision_finding_reason(d, 0));
        }
        if (!sg_decision_complete(d)) {
            printf("        (evaluation incomplete; failed closed)\n");
        }

        sg_decision_free(d);
    }

    sg_worker_free(worker);
    sg_gate_free(gate);

    printf("\n%s\n", failures ? "FAILURES" : "all verdicts as expected");
    return failures ? 1 : 0;
}
