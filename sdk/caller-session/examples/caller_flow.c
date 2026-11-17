/* Integration sequence; provide these platform functions in an audited backend.
 * This file deliberately does not pretend the existing FlashLd implements them. */
#include "fx_caller_session.h"

extern const fxcs_backend project_runtime_backend;
extern const fxcs_app project_business_state;
extern void *project_backend_user;
extern void *project_app_user;
extern void project_yield_after_transfer(void); /* Must never continue old A. */

static fxcs_session session;
static unsigned char checkpoint_work[FXCS_RECORD_HEADER_BYTES + 4096];

int caller_session_initialize(void)
{
    return fxcs_init(&session,&project_runtime_backend,project_backend_user,
                     &project_business_state,project_app_user,
                     checkpoint_work,sizeof(checkpoint_work));
}

int caller_start_external(uint64_t unique_session, uint64_t target, uint32_t menu_policy)
{
    fxcs_request request={unique_session,target,menu_policy};
    int result=fxcs_prepare(&session,&request);
    if(result!=FXCS_OK) return result; /* UNSUPPORTED leaves A untouched. */
    result=fxcs_handoff(&session);
    if(result==FXCS_TRANSFERRED) project_yield_after_transfer();
    return result;
}

int caller_recovery_entry(uint32_t resident_proven_event)
{
    int result=caller_session_initialize();
    if(result!=FXCS_OK) return result;
    result=fxcs_recover(&session,resident_proven_event);
    if(result==FXCS_TRANSFERRED) project_yield_after_transfer();
    return result;
}
