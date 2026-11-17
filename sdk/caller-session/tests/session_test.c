#include "fx_caller_session.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

enum { ALL_CAPS=31 };
typedef struct fixture {
    fxcs_session session;
    unsigned char work[1024], disk[1024]; size_t disk_size;
    fxcs_ticket ticket;
    uint32_t caps, depth, event;
    uint64_t boot, used_session;
    int value, paused, save_count, init_count, restore_count, resume_count;
    int commit_count, handoff_count, verify_count, target_resume_count;
    int fail_save, fail_commit, fail_handoff, fail_restore, fail_consume, fail_resume_target;
    int oversized_save, reenter;
} fixture;

static int inspect(void *u, const fxcs_request *r, fxcs_backend_info *out)
{
    fixture *f=u;
    if(r->session_id==f->used_session) return -1;
    out->boot_id=f->boot; out->capabilities=f->caps; out->active_depth=f->depth; return 0;
}
static int commit(void *u,const fxcs_ticket *ticket,const unsigned char *data,size_t length)
{
    fixture *f=u; f->commit_count++;
    if(f->fail_commit || f->depth || length>sizeof(f->disk)) return -1;
    memcpy(f->disk,data,length); f->disk_size=length; f->ticket=*ticket; f->depth=1; return 0;
}
static int read_record(void *u,unsigned char *out,size_t capacity,size_t *length)
{
    fixture *f=u; if(!f->disk_size) return 1;
    if(f->disk_size>capacity) return -1;
    memcpy(out,f->disk,f->disk_size); *length=f->disk_size; return 0;
}
static int same_ticket(const fxcs_ticket *a,const fxcs_ticket *b)
{ return a->boot_id==b->boot_id && a->session_id==b->session_id && a->caller_id==b->caller_id; }
static int consume(void *u,const fxcs_ticket *ticket)
{
    fixture *f=u; if(f->fail_consume || !same_ticket(ticket,&f->ticket)) return -1;
    f->disk_size=0; f->depth=0; f->used_session=ticket->session_id; return 0;
}
static int handoff(void *u,const fxcs_ticket *t,const fxcs_request *r)
{
    fixture *f=u; assert(same_ticket(t,&f->ticket)); assert(r->target_id==77);
    f->handoff_count++; return f->fail_handoff ? -1 : 0;
}
static int verify(void *u,const fxcs_ticket *t,uint32_t event,uint32_t policy)
{
    fixture *f=u; f->verify_count++;
    assert(policy==FXCS_MENU_RESTORE_CALLER || policy==FXCS_MENU_RESUME_TARGET);
    return same_ticket(t,&f->ticket) && event==f->event &&
        (t->boot_id==f->boot || event==FXCS_OS_RESTART) ? 0 : -1;
}
static int resume_target(void *u,const fxcs_ticket *t)
{ fixture *f=u; assert(same_ticket(t,&f->ticket)); f->target_resume_count++; return f->fail_resume_target ? -1 : 0; }
static int pause_app(void *u) { fixture *f=u; f->paused++; return 0; }
static int save_app(void *u,unsigned char *out,size_t capacity,size_t *written)
{
    fixture *f=u; f->save_count++;
    if(f->reenter) { fxcs_request nested={999,77,FXCS_MENU_RESTORE_CALLER}; assert(fxcs_prepare(&f->session,&nested)==FXCS_BUSY); }
    if(f->fail_save) return -1;
    if(f->oversized_save) { *written=capacity+1; return 0; }
    if(capacity<4) return -1;
    out[0]=(unsigned char)((unsigned)f->value>>24); out[1]=(unsigned char)((unsigned)f->value>>16);
    out[2]=(unsigned char)((unsigned)f->value>>8); out[3]=(unsigned char)f->value;
    *written=4; return 0;
}
static int init_app(void *u) { fixture *f=u; f->init_count++; f->value=0; return 0; }
static int restore_app(void *u,const unsigned char *data,size_t length)
{
    fixture *f=u; f->restore_count++; if(f->fail_restore || length!=4) return -1;
    f->value=(int)(((unsigned)data[0]<<24)|((unsigned)data[1]<<16)|((unsigned)data[2]<<8)|data[3]); return 0;
}
static void resume_app(void *u) { fixture *f=u; f->resume_count++; f->paused=0; }
static const fxcs_backend backend={inspect,commit,read_record,consume,handoff,verify,resume_target};
static const fxcs_app app={42,7,pause_app,save_app,init_app,restore_app,resume_app};
static void init(fixture *f)
{
    memset(f,0,sizeof(*f)); f->caps=ALL_CAPS; f->boot=55; f->value=123456;
    assert(fxcs_init(&f->session,&backend,f,&app,f,f->work,sizeof(f->work))==FXCS_OK);
}
static void cold_entry(fixture *f)
{
    /* Throw away all controller/old application RAM, keeping only durable data
     * and the separately resident backend's proof. */
    memset(&f->session,0xa5,sizeof(f->session)); memset(f->work,0xcc,sizeof(f->work)); f->value=-999;
    assert(fxcs_init(&f->session,&backend,f,&app,f,f->work,sizeof(f->work))==FXCS_OK);
}
static void start(fixture *f,uint32_t policy)
{
    fxcs_request request={123,77,policy};
    assert(fxcs_prepare(&f->session,&request)==FXCS_OK);
    assert(f->paused==1 && f->disk_size==100 && f->depth==1);
    assert(fxcs_handoff(&f->session)==FXCS_TRANSFERRED);
}
static void test_refusal_before_mutation(void)
{
    fixture f; fxcs_request r={123,77,FXCS_MENU_RESTORE_CALLER}; unsigned bit;
    for(bit=0;bit<5;bit++) {
        if(bit==2) continue;
        init(&f); f.caps&=~(1u<<bit); assert(fxcs_prepare(&f.session,&r)==FXCS_UNSUPPORTED);
        assert(!f.paused && !f.commit_count && !f.save_count);
    }
    init(&f); f.depth=1; assert(fxcs_prepare(&f.session,&r)==FXCS_NESTED); assert(!f.save_count);
    init(&f); f.caps&=~FXCS_CAP_MENU_RESUME_TARGET; r.menu_policy=FXCS_MENU_RESUME_TARGET;
    assert(fxcs_prepare(&f.session,&r)==FXCS_UNSUPPORTED); assert(!f.paused);
    init(&f); r.menu_policy=99; assert(fxcs_prepare(&f.session,&r)==FXCS_INVALID); assert(!f.commit_count);
}
static void test_normal_exit_cold_restore(void)
{
    fixture f; init(&f); start(&f,FXCS_MENU_RESUME_TARGET); cold_entry(&f); f.event=FXCS_TARGET_EXIT;
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_OK);
    assert(f.value==123456 && f.init_count==1 && f.restore_count==1 && f.resume_count==1 && !f.disk_size);
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_NO_RECORD);
}
static void test_two_menu_policies(void)
{
    fixture f; init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); cold_entry(&f); f.event=FXCS_MENU_DIRECT_RETURN;
    assert(fxcs_recover(&f.session,FXCS_MENU_DIRECT_RETURN)==FXCS_OK); assert(f.value==123456 && !f.target_resume_count);
    init(&f); start(&f,FXCS_MENU_RESUME_TARGET); cold_entry(&f); f.event=FXCS_MENU_DIRECT_RETURN;
    assert(fxcs_recover(&f.session,FXCS_MENU_DIRECT_RETURN)==FXCS_TRANSFERRED);
    assert(f.disk_size==100 && !f.init_count && !f.restore_count && f.target_resume_count==1);
    cold_entry(&f); f.event=FXCS_TARGET_EXIT; assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_OK); assert(f.value==123456);
}
static void test_save_commit_rollback(void)
{
    fixture f; fxcs_request r={123,77,FXCS_MENU_RESTORE_CALLER}; init(&f); f.fail_save=1;
    assert(fxcs_prepare(&f.session,&r)==FXCS_APPLICATION); assert(!f.paused && !f.commit_count && !f.disk_size);
    init(&f); f.fail_commit=1; assert(fxcs_prepare(&f.session,&r)==FXCS_STORAGE);
    assert(!f.paused && f.resume_count==1 && !f.disk_size && f.session.state==FXCS_IDLE);
    init(&f); f.oversized_save=1; assert(fxcs_prepare(&f.session,&r)==FXCS_BUFFER_SMALL); assert(!f.commit_count && !f.paused);
}
static void test_handoff_and_cancel_failure(void)
{
    fixture f; fxcs_request r={123,77,FXCS_MENU_RESTORE_CALLER}; init(&f); f.fail_handoff=1;
    assert(fxcs_prepare(&f.session,&r)==FXCS_OK); assert(fxcs_handoff(&f.session)==FXCS_BACKEND);
    assert(!f.paused && !f.disk_size && f.value==123456);
    init(&f); assert(fxcs_prepare(&f.session,&r)==FXCS_OK); f.fail_consume=1;
    assert(fxcs_cancel(&f.session)==FXCS_STORAGE); assert(f.paused && f.disk_size && f.session.state==FXCS_FAULT);
    f.fail_consume=0; assert(fxcs_cancel(&f.session)==FXCS_OK); assert(!f.paused && !f.disk_size);
}
static void test_corrupt_truncated_and_foreign_snapshot(void)
{
    fixture f; size_t i;
    for(i=0;i<100;i++) {
        init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); f.disk[i]^=0x80; cold_entry(&f); f.event=FXCS_TARGET_EXIT;
        assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_CORRUPT); assert(!f.init_count && !f.verify_count && f.disk_size==100);
    }
    init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); f.disk_size=99; cold_entry(&f);
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_CORRUPT); assert(!f.init_count);
    init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); cold_entry(&f);
    { fxcs_app wrong=app; wrong.caller_id=43;
      assert(fxcs_init(&f.session,&backend,&f,&wrong,&f,f.work,sizeof(f.work))==FXCS_OK);
      assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_STALE); assert(!f.init_count); }
}
static void test_lifecycle_proof_and_discard(void)
{
    fixture f; init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); cold_entry(&f); f.event=FXCS_FOREIGN_APPLICATION;
    assert(fxcs_recover(&f.session,FXCS_MENU_DIRECT_RETURN)==FXCS_STALE); assert(!f.init_count && f.disk_size);
    assert(fxcs_recover(&f.session,FXCS_FOREIGN_APPLICATION)==FXCS_DISCARDED); assert(!f.disk_size && !f.restore_count);
    init(&f); start(&f,FXCS_MENU_RESUME_TARGET); cold_entry(&f); f.boot++; f.event=FXCS_TARGET_EXIT;
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_STALE); assert(!f.init_count);
    f.event=FXCS_OS_RESTART; assert(fxcs_recover(&f.session,FXCS_OS_RESTART)==FXCS_DISCARDED);
    assert(!f.disk_size && !f.target_resume_count && !f.restore_count);
}
static void test_restore_retry_and_consume_failure(void)
{
    fixture f; init(&f); start(&f,FXCS_MENU_RESTORE_CALLER); cold_entry(&f); f.event=FXCS_TARGET_EXIT; f.fail_restore=1;
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_APPLICATION); assert(f.disk_size && !f.resume_count);
    f.fail_restore=0; f.fail_consume=1; assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_STORAGE);
    assert(f.value==123456 && f.disk_size && !f.resume_count);
    f.fail_consume=0; assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_OK);
    assert(f.value==123456 && !f.disk_size && f.restore_count==3 && f.resume_count==1);
}
static void test_reentry_and_snapshot_capacity(void)
{
    fixture f; fxcs_request r={123,77,FXCS_MENU_RESTORE_CALLER}; init(&f); f.reenter=1;
    assert(fxcs_prepare(&f.session,&r)==FXCS_OK); assert(fxcs_prepare(&f.session,&r)==FXCS_BUSY);
    assert(f.save_count==1 && f.commit_count==1); assert(fxcs_cancel(&f.session)==FXCS_OK);
    assert(fxcs_prepare(&f.session,&r)==FXCS_BACKEND); /* duplicate session ID */
    init(&f); start(&f,FXCS_MENU_RESUME_TARGET); cold_entry(&f);
    assert(fxcs_init(&f.session,&backend,&f,&app,&f,f.work,96)==FXCS_OK);
    assert(fxcs_recover(&f.session,FXCS_TARGET_EXIT)==FXCS_STORAGE); assert(!f.init_count);
}
int main(void)
{
    test_refusal_before_mutation(); test_normal_exit_cold_restore(); test_two_menu_policies();
    test_save_commit_rollback(); test_handoff_and_cancel_failure(); test_corrupt_truncated_and_foreign_snapshot();
    test_lifecycle_proof_and_discard(); test_restore_retry_and_consume_failure(); test_reentry_and_snapshot_capacity();
    puts("caller-session: 9 lifecycle groups and 100 snapshot corruption cases passed"); return 0;
}
