#include <getdns/getdns_extra.h>
#include <stdio.h>

void callback(getdns_context *ctxt, getdns_callback_type_t cb_type,
    getdns_dict *resp, void *userarg, getdns_transaction_t trans_id) {}

int main()
{
    getdns_return_t r;
    getdns_context *ctxt = NULL;

    if ((r = getdns_context_create(&ctxt, 1)))
        fprintf( stderr, "Could not create context: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_address(ctxt, "getdnsapi.net.",
				    NULL, NULL, NULL, callback)))
        fprintf( stderr, "Unable to schedule an address lookup: %s\n"
               , getdns_get_errorstr_by_id(r));
    else
        getdns_context_run(ctxt);

    if (ctxt)
        getdns_context_destroy(ctxt);
    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}
