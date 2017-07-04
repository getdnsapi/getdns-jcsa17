#include <getdns/getdns_extra.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <uv.h>
#include <getdns/getdns_ext_libuv.h>


void callback(getdns_context *ctxt, getdns_callback_type_t cb_type,
    getdns_dict *resp, void *userarg, getdns_transaction_t trans_id)
{
    getdns_return_t r;
    getdns_list    *jaa;     /* The just_address_answers list */
    size_t          i;       /* Variable to iterate over the jaa list */
    getdns_dict    *ad;      /* A dictionary containing an address */

    if (cb_type != GETDNS_CALLBACK_COMPLETE) 
        fprintf( stderr, "Something went wrong with this query: %s\n"
               , getdns_get_errorstr_by_id(cb_type));

    else if ((r = getdns_dict_get_list(resp, "just_address_answers", &jaa)))
        fprintf( stderr, "No addresses in the response dict: %s\n"
               , getdns_get_errorstr_by_id(r));

    else for (i = 0; !getdns_list_get_dict(jaa, i, &ad); i++) {

        getdns_bindata *address;
        char            address_str[1024];

        if ((r = getdns_dict_get_bindata(ad, "address_data", &address)))
            fprintf( stderr, "Could not get address_data: %s\n"
                   , getdns_get_errorstr_by_id(r));

        else if (address->size != 4 && address->size != 16)
            fprintf(stderr, "Unable to determine address type\n");

        else if (! inet_ntop( address->size == 4 ? AF_INET : AF_INET6,
            address->data, address_str, sizeof(address_str)))
            fprintf(stderr, "Could not convert address to string\n");
        else 
            printf("An address of getdnsapi.net is: %s\n", address_str);
    }
    getdns_dict_destroy(resp); /* Safe, because resp is NULL on error */
}


int main()
{
    getdns_return_t r = GETDNS_RETURN_MEMORY_ERROR;
    getdns_context *ctxt = NULL;
    getdns_dict *resp = NULL;
    getdns_bindata *address;
    char address_str[1024];
    uv_loop_t *loop = malloc(sizeof(uv_loop_t));

    if (!loop)
        fprintf( stderr, "Could not allocate event loop\n");

    else if (uv_loop_init(loop))
        fprintf( stderr, "Could not initialize event loop\n");

    else if ((r = getdns_context_create(&ctxt, 1)))
        fprintf( stderr, "Could not create context: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_extension_set_libuv_loop(ctxt, loop)))
        fprintf( stderr, "Unable to set the event loop: %s\n"
               , getdns_get_errorstr_by_id(r));

    else if ((r = getdns_address(ctxt, "getdnsapi.net.", NULL,
                    NULL, NULL, callback)))
        fprintf( stderr, "Unable to schedule an address lookup: %s\n"
               , getdns_get_errorstr_by_id(r));
    else
        uv_run(loop, UV_RUN_DEFAULT);

    if (ctxt)
        getdns_context_destroy(ctxt);
    if (loop) {
        uv_loop_close(loop);
        free(loop);
    }
    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}


