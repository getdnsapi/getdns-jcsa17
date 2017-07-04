#include <getdns/getdns_extra.h>
#include <stdio.h>

int main()
{
    getdns_return_t r;
    getdns_context *ctxt = NULL;

    if ((r = getdns_context_create(&ctxt, 1)))
        fprintf( stderr, "Could not create context: %s\n"
               , getdns_get_errorstr_by_id(r));

    if (ctxt)
        getdns_context_destroy(ctxt);

    return r ? EXIT_FAILURE : EXIT_SUCCESS;
}

