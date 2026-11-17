#include "fx_caller_session.h"
#include <string.h>

static const unsigned char magic[8] = {'F','X','C','A','L','L','0','2'};
static void put32(unsigned char *p, uint32_t n)
{ p[0]=(unsigned char)(n>>24); p[1]=(unsigned char)(n>>16); p[2]=(unsigned char)(n>>8); p[3]=(unsigned char)n; }
static uint32_t get32(const unsigned char *p)
{ return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3]; }
static void put64(unsigned char *p, uint64_t n) { put32(p,(uint32_t)(n>>32)); put32(p+4,(uint32_t)n); }
static uint64_t get64(const unsigned char *p) { return ((uint64_t)get32(p)<<32)|get32(p+4); }
static uint32_t crc(const unsigned char *p, size_t n)
{
    uint32_t v=0xffffffffu; size_t i; unsigned bit;
    for(i=0;i<n;i++) { v^=p[i]; for(bit=0;bit<8;bit++) v=(v>>1)^(0xedb88320u & (0u-(v&1u))); }
    return ~v;
}
static uint32_t required(uint32_t policy)
{
    return FXCS_CAP_RETURN_REINITIALIZE|FXCS_CAP_VERIFIED_EVENTS|FXCS_CAP_ATOMIC_STORE|
        (policy==FXCS_MENU_RESTORE_CALLER ? FXCS_CAP_MENU_RESTORE_CALLER : FXCS_CAP_MENU_RESUME_TARGET);
}
static int policy_ok(uint32_t p) { return p==FXCS_MENU_RESTORE_CALLER || p==FXCS_MENU_RESUME_TARGET; }

int fxcs_init(fxcs_session *s, const fxcs_backend *b, void *bu,
              const fxcs_app *a, void *au, unsigned char *buffer, size_t capacity)
{
    if(!s || !b || !a || !buffer || capacity<FXCS_RECORD_HEADER_BYTES ||
       !a->caller_id || !a->state_schema || !a->pause || !a->save || !a->reinitialize || !a->restore || !a->resume ||
       !b->inspect || !b->commit || !b->read || !b->consume || !b->handoff || !b->verify_event)
        return FXCS_INVALID;
    memset(s,0,sizeof(*s)); s->backend=b; s->backend_user=bu; s->app=a; s->app_user=au;
    s->buffer=buffer; s->capacity=capacity; return FXCS_OK;
}

static void encode(fxcs_session *s, size_t length)
{
    unsigned char *p=s->buffer;
    memset(p,0,FXCS_RECORD_HEADER_BYTES); memcpy(p,magic,8);
    put32(p+8,2); put32(p+12,FXCS_RECORD_HEADER_BYTES); put32(p+16,(uint32_t)(length+FXCS_RECORD_HEADER_BYTES));
    put32(p+20,(uint32_t)length); put32(p+24,crc(p+FXCS_RECORD_HEADER_BYTES,length));
    put32(p+32,s->request.menu_policy); put32(p+36,s->app->state_schema);
    put64(p+40,s->ticket.boot_id); put64(p+48,s->ticket.session_id); put64(p+56,s->ticket.caller_id);
    put64(p+64,s->request.target_id); put32(p+28,crc(p,FXCS_RECORD_HEADER_BYTES));
    s->record_length=length+FXCS_RECORD_HEADER_BYTES;
}

static int decode(fxcs_session *s, size_t length)
{
    unsigned char *p=s->buffer; uint32_t header_crc, payload; size_t i;
    if(length<FXCS_RECORD_HEADER_BYTES || length>s->capacity || memcmp(p,magic,8) ||
       get32(p+8)!=2 || get32(p+12)!=FXCS_RECORD_HEADER_BYTES || get32(p+16)!=length)
        return FXCS_CORRUPT;
    payload=get32(p+20);
    if(payload>FXCS_MAX_STATE_BYTES || payload!=length-FXCS_RECORD_HEADER_BYTES || !policy_ok(get32(p+32)))
        return FXCS_CORRUPT;
    for(i=72;i<FXCS_RECORD_HEADER_BYTES;i++) if(p[i]) return FXCS_CORRUPT;
    header_crc=get32(p+28); put32(p+28,0);
    if(header_crc!=crc(p,FXCS_RECORD_HEADER_BYTES)) { put32(p+28,header_crc); return FXCS_CORRUPT; }
    put32(p+28,header_crc);
    if(get32(p+24)!=crc(p+FXCS_RECORD_HEADER_BYTES,payload)) return FXCS_CORRUPT;
    s->ticket.boot_id=get64(p+40); s->ticket.session_id=get64(p+48); s->ticket.caller_id=get64(p+56);
    if(!s->ticket.boot_id || !s->ticket.session_id || !get64(p+64)) return FXCS_CORRUPT;
    if(s->ticket.caller_id!=s->app->caller_id || get32(p+36)!=s->app->state_schema) return FXCS_STALE;
    s->request.session_id=s->ticket.session_id; s->request.target_id=get64(p+64);
    s->request.menu_policy=get32(p+32); s->record_length=length; return FXCS_OK;
}

int fxcs_prepare(fxcs_session *s, const fxcs_request *r)
{
    fxcs_backend_info info; size_t length=0, capacity; int rc;
    if(!s || !s->backend || !r || !r->session_id || !r->target_id || !policy_ok(r->menu_policy)) return FXCS_INVALID;
    if(s->state!=FXCS_IDLE) return FXCS_BUSY;
    memset(&info,0,sizeof(info));
    if(s->backend->inspect(s->backend_user,r,&info)!=0) return FXCS_BACKEND;
    if(info.active_depth) return FXCS_NESTED;
    if(!info.boot_id || (info.capabilities&required(r->menu_policy))!=required(r->menu_policy) ||
       (r->menu_policy==FXCS_MENU_RESUME_TARGET && !s->backend->resume_target)) return FXCS_UNSUPPORTED;
    s->state=FXCS_SAVING; s->request=*r;
    s->ticket.boot_id=info.boot_id; s->ticket.session_id=r->session_id; s->ticket.caller_id=s->app->caller_id;
    if(s->app->pause(s->app_user)!=0) { s->state=FXCS_IDLE; return FXCS_APPLICATION; }
    capacity=s->capacity-FXCS_RECORD_HEADER_BYTES;
    if(capacity>FXCS_MAX_STATE_BYTES) capacity=FXCS_MAX_STATE_BYTES;
    rc=s->app->save(s->app_user,s->buffer+FXCS_RECORD_HEADER_BYTES,capacity,&length);
    if(rc || length>capacity) {
        s->app->resume(s->app_user); s->state=FXCS_IDLE;
        return length>capacity ? FXCS_BUFFER_SMALL : FXCS_APPLICATION;
    }
    encode(s,length);
    if(s->backend->commit(s->backend_user,&s->ticket,s->buffer,s->record_length)!=0) {
        s->app->resume(s->app_user); s->state=FXCS_IDLE; return FXCS_STORAGE;
    }
    s->state=FXCS_PREPARED; return FXCS_OK;
}

int fxcs_cancel(fxcs_session *s)
{
    if(!s || (s->state!=FXCS_PREPARED && s->state!=FXCS_FAULT)) return FXCS_BUSY;
    if(s->backend->consume(s->backend_user,&s->ticket)!=0) { s->state=FXCS_FAULT; return FXCS_STORAGE; }
    s->state=FXCS_IDLE; s->app->resume(s->app_user); return FXCS_OK;
}

int fxcs_handoff(fxcs_session *s)
{
    int rc;
    if(!s || s->state!=FXCS_PREPARED) return FXCS_BUSY;
    /* Set before transfer; real hardware may not return here. */
    s->state=FXCS_TARGET_ACTIVE;
    rc=s->backend->handoff(s->backend_user,&s->ticket,&s->request);
    if(rc==0) return FXCS_TRANSFERRED;
    /* A nonzero backend result guarantees no transfer and caller RAM intact. */
    s->state=FXCS_PREPARED; rc=fxcs_cancel(s);
    return rc==FXCS_OK ? FXCS_BACKEND : rc;
}

int fxcs_recover(fxcs_session *s, uint32_t event)
{
    size_t length=0; int rc;
    if(!s || !s->backend || event<FXCS_TARGET_EXIT || event>FXCS_OS_RESTART) return FXCS_INVALID;
    if(s->state!=FXCS_IDLE && s->state!=FXCS_RECOVERABLE) return FXCS_BUSY;
    rc=s->backend->read(s->backend_user,s->buffer,s->capacity,&length);
    if(rc==1) return FXCS_NO_RECORD;
    if(rc!=0) return FXCS_STORAGE;
    rc=decode(s,length); if(rc!=FXCS_OK) return rc;
    /* The backend decides whether this is a direct MENU return, restart, or a
     * different foreground app. The event argument alone is never evidence. */
    if(s->backend->verify_event(s->backend_user,&s->ticket,event,s->request.menu_policy)!=0) return FXCS_STALE;
    if(event==FXCS_FOREIGN_APPLICATION || event==FXCS_OS_RESTART) {
        if(s->backend->consume(s->backend_user,&s->ticket)!=0) return FXCS_STORAGE;
        s->state=FXCS_IDLE; return FXCS_DISCARDED;
    }
    s->state=FXCS_RECOVERABLE;
    if(event==FXCS_MENU_DIRECT_RETURN && s->request.menu_policy==FXCS_MENU_RESUME_TARGET) {
        if(!s->backend->resume_target) return FXCS_UNSUPPORTED;
        if(s->backend->resume_target(s->backend_user,&s->ticket)!=0) return FXCS_BACKEND;
        s->state=FXCS_TARGET_ACTIVE; return FXCS_TRANSFERRED;
    }
    if(s->app->reinitialize(s->app_user)!=0 ||
       s->app->restore(s->app_user,s->buffer+FXCS_RECORD_HEADER_BYTES,length-FXCS_RECORD_HEADER_BYTES)!=0)
        return FXCS_APPLICATION;
    /* Consume after successful restoration. If removal fails, recovery can be
     * retried: reinitialize/restore must not duplicate external side effects. */
    if(s->backend->consume(s->backend_user,&s->ticket)!=0) return FXCS_STORAGE;
    s->state=FXCS_IDLE; s->app->resume(s->app_user); return FXCS_OK;
}

const char *fxcs_error_text(int code)
{
    switch(code) {
    case FXCS_OK:return "ok"; case FXCS_TRANSFERRED:return "transferred; caller must yield";
    case FXCS_NO_RECORD:return "no saved session"; case FXCS_DISCARDED:return "old session discarded";
    case FXCS_INVALID:return "invalid interface or request"; case FXCS_UNSUPPORTED:return "backend cannot preserve the requested caller lifecycle";
    case FXCS_NESTED:return "nested calls are not supported"; case FXCS_BUSY:return "session is busy";
    case FXCS_STORAGE:return "transactional storage failed"; case FXCS_CORRUPT:return "snapshot is corrupt";
    case FXCS_STALE:return "snapshot or lifecycle evidence does not match"; case FXCS_APPLICATION:return "caller save or restore failed";
    case FXCS_BACKEND:return "runtime transfer failed"; case FXCS_BUFFER_SMALL:return "snapshot exceeds supplied buffer";
    default:return "unknown session result";
    }
}
