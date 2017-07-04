#include <getdns/getdns_extra.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <uv.h>
#include <getdns/getdns_ext_libuv.h>

struct dane_query_st {
    getdns_dict          *addrs_response;
    getdns_transaction_t  addrs_transaction_id;
    getdns_dict          *tlsas_response;
    getdns_transaction_t  tlsas_transaction_id;
};

void abort_connection(struct dane_query_st *state)
{
    getdns_dict_destroy(state->addrs_response);
    getdns_dict_destroy(state->tlsas_response);
    fprintf(stderr, "DNS failure\n");
}

void setup_connection(struct dane_query_st *state)
{
    uint32_t status;

    if (getdns_dict_get_int(state->tlsas_response, "status", &status)
    ||  status == GETDNS_RESPSTATUS_ALL_BOGUS_ANSWERS) {

        abort_connection(state);
        return;
    }
    printf("DNS lookups were successful!\n");

    /* Schedule opening the TLS connection to the addresses (if any)
     * and verification with the received TLSAs (if any)
     */
}

void addresses_callback(getdns_context *ctxt, getdns_callback_type_t cb_type,
    getdns_dict *resp, void *userarg, getdns_transaction_t trans_id)
{
    struct dane_query_st *state = (struct dane_query_st *)userarg;

    if (cb_type != GETDNS_CALLBACK_COMPLETE) {
        /* Something went wrong,
         * Cancel the TLSA query if it hasn't finished yet.
         * Then abort the connection.
         */
        if (! state->tlsas_response)
            (void) getdns_cancel_callback(
                ctxt, state->tlsas_transaction_id);

        abort_connection(state);
        return;
    }
    state->addrs_response = resp;
    if (state->tlsas_response)
        setup_connection(state);
    else
        ; /* Wait for TLSA lookup to complete */
}

void tlsas_callback(getdns_context *ctxt, getdns_callback_type_t cb_type,
    getdns_dict *resp, void *userarg, getdns_transaction_t trans_id)
{
    struct dane_query_st *state = (struct dane_query_st *)userarg;

    if (cb_type != GETDNS_CALLBACK_COMPLETE) {
        /* Something went wrong,
         * Cancel the TLSA query if it hasn't finished yet.
         * Then abort the connection.
         */
        if (! state->addrs_response)
            (void) getdns_cancel_callback(
                ctxt, state->addrs_transaction_id);

        abort_connection(state);
        return;
    }
    state->tlsas_response = resp;
    if (state->addrs_response)
        setup_connection(state);
    else
        ; /* Wait for address lookup to complete */
}

int main()
{
    getdns_return_t r;
    getdns_context *ctxt = NULL;
    uv_loop_t loop;
    getdns_dict *ext;
    struct dane_query_st state = { NULL, 0, NULL, 0 };

    if (uv_loop_init(&loop)) {
        fprintf( stderr, "Could not initialize event loop\n");
        return EXIT_FAILURE;
    }
    else if ((r = getdns_context_create(&ctxt, 1)))
        fprintf( stderr, "Could not create context: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_extension_set_libuv_loop(ctxt, &loop)))
        fprintf( stderr, "Unable to set the event loop: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_context_set_resolution_type(
                    ctxt, GETDNS_RESOLUTION_STUB)))
        fprintf( stderr, "Could not set stub resolution modus: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_address( ctxt, "getdnsapi.net.", NULL
                                , &state
                                , &state.addrs_transaction_id
                                , addresses_callback)))
        fprintf( stderr, "Unable to schedule an address lookup: %s\n"
               , getdns_get_errorstr_by_id(r));
#if 0
    else if (!(ext = getdns_dict_create())) {
        fprintf( stderr, "Could not allocate extensions dict\n");
        r = GETDNS_RETURN_MEMORY_ERROR;
    }
    else if ((r = getdns_dict_set_int(ext, "dnssec_return_only_secure"
                                         , GETDNS_EXTENSION_TRUE))
         ||  (r = getdns_dict_set_int(ext, "dnssec_roadblock_avoidance"
                                         , GETDNS_EXTENSION_TRUE)))
        fprintf( stderr, "Could not populate extensions dict: %s\n"
               , getdns_get_errorstr_by_id(r));
#endif
    else if ((r = getdns_str2dict(
		"{ dnssec_return_only_secure : GETDNS_EXTENSION_TRUE "
		", dnssec_roadblock_avoidance: GETDNS_EXTENSION_TRUE }", &ext)))

        fprintf( stderr, "Could not create/populate extensions dict: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_general( ctxt, "_443._tcp.getdnsapi.net."
                                , GETDNS_RRTYPE_TLSA, ext
                                , &state
                                , &state.tlsas_transaction_id
                                , tlsas_callback)))
        fprintf( stderr, "Unable to schedule a TLSA lookup: %s\n"
               , getdns_get_errorstr_by_id(r));
    else
        uv_run(&loop, UV_RUN_DEFAULT);

    if (ext)
        getdns_dict_destroy(ext);
    if (ctxt)
        getdns_context_destroy(ctxt);
    uv_loop_close(&loop);
    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
