/**
 * @file svd.c
 * Main file of the project.
 * It containes main initializtions and main cycle start.
 * */

/* Includes {{{ */
#include "svd.h"
#include "svd_cfg.h"
#include "svd_ua.h"
#include "svd_atab.h"
#include "svd_server_if.h"
#include "svd_if.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <stdarg.h>
#include <syslog.h>
#include <signal.h>
#include <netinet/ip.h>
#include <errno.h>
#include <sys/stat.h>
/*}}}*/

/** Name of the daemon (using in logs).*/
#define DAEMON_NAME "svd"

unsigned int g_f_cnt= 0;
unsigned int g_f_offset = 0;

/** Create svd structure.*/
static svd_t * svd_create(ab_t * const ab);
/** Destroy svd structure.*/
static void svd_destroy( svd_t ** svd );
/** Logging function.*/
static void svd_logger(void *logarg, char const *format, va_list ap);
/** Set logging function.*/
static void svd_log_set( int const level, int const debug);

/* svd pointer for termination handler */
static svd_t * main_svd;
/* termination handler */
static void term_handler(int signum)
{
  svd_shutdown(main_svd);
}

/**
 * Main.
 *
 * \param[in] argc 	arguments count
 * \param[in] argv 	arguments values
 * \retval 0 	etherything is fine
 * \retval -1 	error occures
 * \remark
 *		In real it shold never returns if etherything is fine
 *		because of main cycle.
 */
int
main (int argc, char ** argv)
{/*{{{*/
	svd_t *svd;
	ab_t * ab = NULL;
	int err = 0;
	int nothing_to_do;

	nothing_to_do = startup_init( argc, argv );
	if( nothing_to_do ){
		goto __startup;
	}

	su_init();

	/* preliminary log settings */
	if(g_so.debug_level == -1){
		/* debug do not set */
		openlog( DAEMON_NAME, LOG_PID, LOG_LOCAL5 );
		syslog( LOG_INFO, "starting" );
		svd_log_set (0,0);
	} else {
		/* debug to stderr is set */
		svd_log_set (g_so.debug_level, 1);
	}

	/* init hardware structures */
	ab = ab_create();
	if( !ab){
		SU_DEBUG_0 ((LOG_FNC_A(ab_g_err_str)));
		goto __su;
	}

	/* create svd structure */
	/* uses !!g_conf */
	svd = svd_create (ab);
	if (svd == NULL) {
		goto __conf;
	}

	/* create interface */
	err = svd_create_interface(svd);
	if(err){
		goto __if;
	}

	/* set termination handler to shutdown svd */
	main_svd = svd;
	signal(SIGTERM, term_handler);

	/* run main cycle */
	su_root_run (svd->root);

__if:
	svd_destroy_interface(svd);
	svd_destroy (&svd);
__conf:
	svd_conf_destroy ();
	ab_destroy (&ab);
__su:
	su_deinit ();
	syslog( LOG_NOTICE, "terminated" );
	closelog();
__startup:
	startup_destroy (argc, argv);
	return err;
}/*}}}*/

/**
 * Timer callback, log statistics
 * \param[in] magic	svd pointer.
 * \param[in] t		initiator timer.
 * \param[in] arg	not used
 */
void timer_cb (su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg)
{/*{{{*/
	svd_t *svd = magic;
	nta_agent_t *nta = nua_get_agent(svd->nua);

	usize_t irq_hash = -1, orq_hash = -1, leg_hash = -1;
	usize_t recv_msg = -1, sent_msg = -1;
	usize_t recv_request = -1, recv_response = -1;
	usize_t bad_message = -1, bad_request = -1, bad_response = -1;
	usize_t drop_request = -1, drop_response = -1;
	usize_t client_tr = -1, server_tr = -1, dialog_tr = -1;
	usize_t acked_tr = -1, canceled_tr = -1;
	usize_t trless_request = -1, trless_to_tr = -1, trless_response = -1;
	usize_t trless_200 = -1, merged_request = -1;
	usize_t sent_request = -1, sent_response = -1;
	usize_t retry_request = -1, retry_response = -1, recv_retry = -1;
	usize_t tout_request = -1, tout_response = -1;
	usize_t in_completed = -1;
	usize_t in_final_failed = -1;
	usize_t in_inv_completed = -1;
	usize_t in_inv_confirmed = -1;
	usize_t in_preliminary = -1;
	usize_t in_proceeding = -1;
	usize_t in_terminated = -1;
	usize_t out_completed = -1;
	usize_t out_delayed = -1;
	usize_t out_inv_calling = -1;
	usize_t out_inv_completed = -1;
	usize_t out_inv_proceeding = -1;
	usize_t out_resolving = -1;
	usize_t out_terminated = -1;

	nta_agent_get_stats(nta,
			NTATAG_S_IRQ_HASH_REF(irq_hash),
			NTATAG_S_ORQ_HASH_REF(orq_hash),
			NTATAG_S_LEG_HASH_REF(leg_hash),
			NTATAG_S_RECV_MSG_REF(recv_msg),
			NTATAG_S_SENT_MSG_REF(sent_msg),
			NTATAG_S_RECV_REQUEST_REF(recv_request),
			NTATAG_S_RECV_RESPONSE_REF(recv_response),
			NTATAG_S_BAD_MESSAGE_REF(bad_message),
			NTATAG_S_BAD_REQUEST_REF(bad_request),
			NTATAG_S_BAD_RESPONSE_REF(bad_response),
			NTATAG_S_DROP_REQUEST_REF(drop_request),
			NTATAG_S_DROP_RESPONSE_REF(drop_response),
			NTATAG_S_CLIENT_TR_REF(client_tr),
			NTATAG_S_SERVER_TR_REF(server_tr),
			NTATAG_S_DIALOG_TR_REF(dialog_tr),
			NTATAG_S_ACKED_TR_REF(acked_tr),
			NTATAG_S_CANCELED_TR_REF(canceled_tr),
			NTATAG_S_TRLESS_REQUEST_REF(trless_request),
			NTATAG_S_TRLESS_TO_TR_REF(trless_to_tr),
			NTATAG_S_TRLESS_RESPONSE_REF(trless_response),
			NTATAG_S_TRLESS_200_REF(trless_200),
			NTATAG_S_MERGED_REQUEST_REF(merged_request),
			NTATAG_S_SENT_REQUEST_REF(sent_request),
			NTATAG_S_SENT_RESPONSE_REF(sent_response),
			NTATAG_S_RETRY_REQUEST_REF(retry_request),
			NTATAG_S_RETRY_RESPONSE_REF(retry_response),
			NTATAG_S_RECV_RETRY_REF(recv_retry),
			NTATAG_S_TOUT_REQUEST_REF(tout_request),
			NTATAG_S_TOUT_RESPONSE_REF(tout_response),
			NTATAG_Q_IN_COMPLETED_REF(in_completed),
			NTATAG_Q_IN_FINAL_FAILED_REF(in_final_failed),
			NTATAG_Q_IN_INV_COMPLETED_REF(in_inv_completed),
			NTATAG_Q_IN_INV_CONFIRMED_REF(in_inv_confirmed),
			NTATAG_Q_IN_PRELIMINARY_REF(in_preliminary),
			NTATAG_Q_IN_PROCEEDING_REF(in_proceeding),
			NTATAG_Q_IN_TERMINATED_REF(in_terminated),
			NTATAG_Q_OUT_COMPLETED_REF(out_completed),
			NTATAG_Q_OUT_DELAYED_REF(out_delayed),
			NTATAG_Q_OUT_INV_CALLING_REF(out_inv_calling),
			NTATAG_Q_OUT_INV_COMPLETED_REF(out_inv_completed),
			NTATAG_Q_OUT_INV_PROCEEDING_REF(out_inv_proceeding),
			NTATAG_Q_OUT_RESOLVING_REF(out_resolving),
			NTATAG_Q_OUT_TERMINATED_REF(out_terminated),
			TAG_END());

	SU_DEBUG_9(("timer_cb: irq_hash=%zd\n", irq_hash));
	SU_DEBUG_9(("timer_cb: orq_hash=%zd\n", orq_hash));
	SU_DEBUG_9(("timer_cb: leg_hash=%zd\n", leg_hash));
	SU_DEBUG_9(("timer_cb: recv_msg=%zd\n", recv_msg));
	SU_DEBUG_9(("timer_cb: sent_msg=%zd\n", sent_msg));
	SU_DEBUG_9(("timer_cb: recv_request=%zd\n", recv_request));
	SU_DEBUG_9(("timer_cb: recv_response=%zd\n", recv_response));
	SU_DEBUG_9(("timer_cb: bad_message=%zd\n", bad_message));
	SU_DEBUG_9(("timer_cb: bad_request=%zd\n", bad_request));
	SU_DEBUG_9(("timer_cb: drop_request=%zd\n", drop_request));
	SU_DEBUG_9(("timer_cb: drop_response=%zd\n", drop_response));
	SU_DEBUG_9(("timer_cb: client_tr=%zd\n", client_tr));
	SU_DEBUG_9(("timer_cb: server_tr=%zd\n", server_tr));
	SU_DEBUG_9(("timer_cb: dialog_tr=%zd\n", dialog_tr));
	SU_DEBUG_9(("timer_cb: acked_tr=%zd\n", acked_tr));
	SU_DEBUG_9(("timer_cb: canceled_tr=%zd\n", canceled_tr));
	SU_DEBUG_9(("timer_cb: trless_request=%zd\n", trless_request));
	SU_DEBUG_9(("timer_cb: trless_to_tr=%zd\n", trless_to_tr));
	SU_DEBUG_9(("timer_cb: trless_response=%zd\n", trless_response));
	SU_DEBUG_9(("timer_cb: trless_200=%zd\n", trless_200));
	SU_DEBUG_9(("timer_cb: merged_request=%zd\n", merged_request));
	SU_DEBUG_9(("timer_cb: sent_request=%zd\n", sent_request));
	SU_DEBUG_9(("timer_cb: sent_response=%zd\n", sent_response));
	SU_DEBUG_9(("timer_cb: retry_request=%zd\n", retry_request));
	SU_DEBUG_9(("timer_cb: retry_response=%zd\n", retry_response));
	SU_DEBUG_9(("timer_cb: recv_retry=%zd\n", recv_retry));
	SU_DEBUG_9(("timer_cb: tout_request=%zd\n", tout_request));
	SU_DEBUG_9(("timer_cb: tout_response=%zd\n", tout_response));
	SU_DEBUG_9(("timer_cb: in_completed=%zd\n", in_completed));
	SU_DEBUG_9(("timer_cb: in_final_failed=%zd\n", in_final_failed));
	SU_DEBUG_9(("timer_cb: in_inv_completed=%zd\n", in_inv_completed));
	SU_DEBUG_9(("timer_cb: in_inv_confirmed=%zd\n", in_inv_confirmed));
	SU_DEBUG_9(("timer_cb: in_preliminary=%zd\n", in_preliminary));
	SU_DEBUG_9(("timer_cb: in_proceeding=%zd\n", in_proceeding));
	SU_DEBUG_9(("timer_cb: in_terminated=%zd\n", in_terminated));
	SU_DEBUG_9(("timer_cb: out_completed=%zd\n", out_completed));
	SU_DEBUG_9(("timer_cb: out_delayed=%zd\n", out_delayed));
	SU_DEBUG_9(("timer_cb: out_inv_calling=%zd\n", out_inv_calling));
	SU_DEBUG_9(("timer_cb: out_inv_completed=%zd\n", out_inv_completed));
	SU_DEBUG_9(("timer_cb: out_inv_proceeding=%zd\n", out_inv_proceeding));
	SU_DEBUG_9(("timer_cb: out_resolving=%zd\n", out_resolving));
	SU_DEBUG_9(("timer_cb: out_terminated=%zd\n", out_terminated));

        su_timer_set(svd->tmr, timer_cb, NULL);
}/*}}}*/

/**
 * Create the svd structure with all appropriate initializations.
 *
 * \retval NULL 			something nasty happens
 * \retval valid_pointer 	new svd structure
 * \remark
 *		It init`s the internal ab structure
 *  	It calls all appropriate functions to create sofia-sip objects
 *  	It uses \ref g_conf values
 */
static svd_t *
svd_create (ab_t * const ab)
{/*{{{*/
	svd_t * svd;
	int tos;
	int err;
DFS
	svd = malloc( sizeof(*svd) );
	if ( !svd) {
    		SU_DEBUG_0 (("svd_create() not enough memory\n" VA_NONE));
		goto __exit_fail;
	}

	memset (svd, 0, sizeof(*svd));

	/* svd home initialization */
	if(su_home_init(svd->home) != 0){
    		SU_DEBUG_0 (("svd_create() su_home_init() failed\n" VA_NONE));
		goto __exit_fail;
	}

	/* read svd *.conf files */
	err = svd_conf_init (ab, svd->home);
	if (err){
		goto __exit_fail;
	}

	/* change log level, if it is not debug mode, from config sets */
	if (g_so.debug_level == -1){
		svd_log_set (g_conf.log_level, 0);
	}

	/* extended SIP parser */
	if(sip_update_default_mclass(sip_extend_mclass(NULL)) < 0) {
		SU_DEBUG_0 (("svd_create() sip_update_default_mclass() failed\n" VA_NONE));
		goto __exit_fail;
	}

	/* svd root creation */
	svd->root = su_root_create (svd);
	if (svd->root == NULL) {
    		SU_DEBUG_0 (("svd_create() su_root_create() failed\n" VA_NONE));
		goto __exit_fail;
	}

	svd->tmr = su_timer_create(su_root_task(svd->root), 60000);
	if( !svd->tmr){
		SU_DEBUG_0 (("svd_create() su_timer_create() failed\n" VA_NONE));
	}

	/* init svd->ab with existing structure */
	svd->ab = ab;

	/* create ab structure of svd and handle callbacks */
	/* uses !!g_cnof */
	err = svd_atab_create (svd);
	if( err ) {
		goto __exit_fail;
	}

	/* launch the SIP stack */
	/* *
	 * NUTAG_AUTOANSWER (1)
	 * NUTAG_PROXY (),
	 * NUTAG_AUTH ("scheme""realm""user""password"),
	 * NUTAG_AUTHTIME (3600),
	 * NUTAG_M_DISPLAY (),
	 * */
	//tos = g_conf.sip_tos & IPTOS_TOS_MASK;
	tos = g_conf.sip_tos & 0xFF;
	char *local_ip=NULL;
	if (g_conf.local_ip) {
		asprintf(&local_ip, "sip:%s", g_conf.local_ip);
		SU_DEBUG_5(("using NUTAG_URL %s\n",local_ip));
	}

	svd->nua = nua_create (svd->root, svd_nua_callback, svd,
			SIPTAG_USER_AGENT_STR ("svd VoIP agent"),
			SOATAG_AF (SOA_AF_IP4_IP6),
			TPTAG_TOS (tos),
			NUTAG_ALLOW ("INFO"),
			NUTAG_AUTOALERT (1),
			NUTAG_ENABLEMESSAGE (1),
			NUTAG_ENABLEINVITE (1),
			NUTAG_EARLY_MEDIA(1),
			TAG_IF (!local_ip, NUTAG_DETECT_NETWORK_UPDATES (NUA_NW_DETECT_TRY_FULL)),
			TAG_IF (local_ip, NUTAG_URL(local_ip)),
			//TAG_IF (g_conf.local_ip, SIPTAG_VIA_STR(g_conf.local_ip)),
			TAG_IF (g_conf.local_ip, SOATAG_ADDRESS(g_conf.local_ip)),
			TAG_NULL () );
	if (!svd->nua) {
		SU_DEBUG_0 (("Network is not initialized\n" VA_NONE));
		goto __exit_fail;
	}


	nua_set_params(svd->nua,
		      NUTAG_OUTBOUND ("gruuize no-outbound validate "
				      "natify use-rport options-keepalive"),
		      TAG_NULL () );

	svd_refresh_registration (svd);
        su_timer_set(svd->tmr, timer_cb, NULL);
	nua_get_params(svd->nua, TAG_ANY(), TAG_NULL());
DFE
	return svd;
__exit_fail:
DFE
	if(svd){
		svd_destroy (&svd);
	}
	return NULL;
}/*}}}*/

/**
 * Correct destroy function for svd structure
 *
 * \param[in] svd 	pointer to pointer to svd structure
 * 		that should be destroyed
 * \remark
 * 		It destroy the internal ab structure
 * 		It calls all appropriate functions to destroy sofia-sip objects
 * 		It destroys the structure and sets the pointer *svd to NULL
 */
static void
svd_destroy( svd_t ** svd )
{/*{{{*/
DFS
	if(*svd){
		svd_atab_delete (*svd);

		if ((*svd)->tmr){
			su_timer_destroy((*svd)->tmr);
		}
		if((*svd)->nua){
			svd_shutdown (*svd);
		}
		if((*svd)->root){
			su_root_destroy ((*svd)->root);
		}
		if((*svd)->home){
			su_home_deinit ((*svd)->home);
		}

		free (*svd);
		*svd = NULL;
	}
DFE
}/*}}}*/

/**
 * Logging callback function
 *
 * \param[in] logarg 	debug value or (-1) if logging is off
 * \param[in] format 	message format (internal sofia log value)
 * \param[in] ap 		message arguments (internal sofia log value)
 * \remark
 *		It calls for every log action and make a decision what to do.
 */
static void
svd_logger(void *logarg, char const *format, va_list ap)
{/*{{{*/
	if( (int)logarg == -1){
		/* do not log anything */
		return;
	} else if ( (int)logarg ) {
		/* debug is on - log to stderr */
		vfprintf(stderr, format, ap);
	} else {
		/* debug is off - standart log */
		vsyslog (LOG_INFO, format, ap);
	}
}/*}}}*/

/**
 * Sets the log configuration
 *
 * \param[in] level
 *		\arg \c -1 - do not log anything
 *		\arg \c 0 - very pure logs to \c 9 - very verbose
 * \param[in] debug
 *		\arg \c 1 - log to stderr or
 *		\arg \c 0 - log to jornal
 * \remark
 *		It attaches the callback logger function with proper params and uses
 *		sofia sip logging system
 */
static void
svd_log_set( int const level, int const debug)
{/*{{{*/
	if (level == -1){
 		/* do not log anything */
		su_log_set_level (NULL, 0);
		su_log_redirect (NULL, svd_logger, (void*)-1);
	} else {
		su_log_set_level (NULL, level);
		su_log_redirect (NULL,svd_logger,(void*)debug);
	}
}/*}}}*/

