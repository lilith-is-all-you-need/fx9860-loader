#ifndef FX_CALLER_SESSION_H
#define FX_CALLER_SESSION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Business-state coordination only. This library does NOT save the SH stack,
 * map memory, install VBR handlers, or make the current FlashLd a callable backend. */
#define FXCS_RECORD_HEADER_BYTES 96u
#define FXCS_MAX_STATE_BYTES 65536u

enum fxcs_result {
    FXCS_OK = 0, FXCS_TRANSFERRED = 1, FXCS_NO_RECORD = 2, FXCS_DISCARDED = 3,
    FXCS_INVALID = -1, FXCS_UNSUPPORTED = -2, FXCS_NESTED = -3,
    FXCS_BUSY = -4, FXCS_STORAGE = -5, FXCS_CORRUPT = -6,
    FXCS_STALE = -7, FXCS_APPLICATION = -8, FXCS_BACKEND = -9,
    FXCS_BUFFER_SMALL = -10
};

enum fxcs_menu_policy { FXCS_MENU_RESTORE_CALLER = 1, FXCS_MENU_RESUME_TARGET = 2 };
enum fxcs_event { FXCS_TARGET_EXIT = 1, FXCS_MENU_DIRECT_RETURN = 2,
                  FXCS_FOREIGN_APPLICATION = 3, FXCS_OS_RESTART = 4 };
enum fxcs_state { FXCS_IDLE = 0, FXCS_SAVING, FXCS_PREPARED,
                  FXCS_TARGET_ACTIVE, FXCS_RECOVERABLE, FXCS_FAULT };

/* Advertise these only for an implemented, tested runtime adapter. */
enum fxcs_capability {
    FXCS_CAP_RETURN_REINITIALIZE = 1u << 0,
    FXCS_CAP_MENU_RESTORE_CALLER = 1u << 1,
    FXCS_CAP_MENU_RESUME_TARGET = 1u << 2,
    FXCS_CAP_VERIFIED_EVENTS = 1u << 3,
    FXCS_CAP_ATOMIC_STORE = 1u << 4
};

typedef struct fxcs_ticket {
    uint64_t boot_id, session_id, caller_id;
} fxcs_ticket;

typedef struct fxcs_request {
    uint64_t session_id; /* Nonzero, unique for this caller/boot. Backend verifies it. */
    uint64_t target_id;  /* Adapter-owned target identity, not a pointer. */
    uint32_t menu_policy;
} fxcs_request;

typedef struct fxcs_backend_info {
    uint64_t boot_id;
    uint32_t capabilities, active_depth;
} fxcs_backend_info;

typedef struct fxcs_app {
    uint64_t caller_id;
    uint32_t state_schema;
    int (*pause)(void *user);
    int (*save)(void *user, unsigned char *out, size_t capacity, size_t *written);
    int (*reinitialize)(void *user);
    /* Must be idempotent: restore can repeat after an interrupted consume. */
    int (*restore)(void *user, const unsigned char *data, size_t length);
    void (*resume)(void *user);
} fxcs_app;

typedef struct fxcs_backend {
    /* Read-only. Reject reused session IDs; report system-wide active depth. */
    int (*inspect)(void *user, const fxcs_request *request, fxcs_backend_info *info);
    /* Atomic durable commit: error must leave prior committed data unchanged.
     * Must claim the single session slot atomically, rejecting a competing claim. */
    int (*commit)(void *user, const fxcs_ticket *ticket, const unsigned char *data, size_t length);
    /* Returns 0=read, 1=absent, negative=error. Reject oversize without truncation. */
    int (*read)(void *user, unsigned char *out, size_t capacity, size_t *length);
    /* Compare ticket and consume atomically. Error retains the record. */
    int (*consume)(void *user, const fxcs_ticket *ticket);
    /* Hardware success normally never returns on the old caller stack. An
     * asynchronous/simulation adapter may return 0: caller must yield at once. */
    int (*handoff)(void *user, const fxcs_ticket *ticket, const fxcs_request *request);
    /* Read-only proof from the resident runtime, NOT caller-selected evidence.
     * Confirm boot/token/foreground continuity and caller mapping ownership.
     * TARGET_EXIT or MENU_RESTORE must already have stopped target resources. */
    int (*verify_event)(void *user, const fxcs_ticket *ticket, uint32_t event, uint32_t policy);
    int (*resume_target)(void *user, const fxcs_ticket *ticket);
} fxcs_backend;

typedef struct fxcs_session {
    const fxcs_backend *backend;
    const fxcs_app *app;
    void *backend_user, *app_user;
    unsigned char *buffer;
    size_t capacity, record_length;
    fxcs_ticket ticket;
    fxcs_request request;
    uint32_t state;
} fxcs_session;

int fxcs_init(fxcs_session *, const fxcs_backend *, void *backend_user,
              const fxcs_app *, void *app_user, unsigned char *buffer, size_t capacity);
int fxcs_prepare(fxcs_session *, const fxcs_request *);
int fxcs_handoff(fxcs_session *);
int fxcs_cancel(fxcs_session *); /* Prepared only; resumes the still-live caller. */
int fxcs_recover(fxcs_session *, uint32_t event); /* Call after source entry/reinit. */
const char *fxcs_error_text(int result);

#ifdef __cplusplus
}
#endif
#endif
