/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "rpc_specification.h"

bool_t
xdr_rpc_CommandBuf (XDR *xdrs, rpc_CommandBuf *objp)
{
	 if (!xdr_vector (xdrs, (char *)objp->buffer, 4096,
		sizeof (char), (xdrproc_t) xdr_char))
		 return FALSE;
	return TRUE;
}
