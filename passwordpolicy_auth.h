/*-------------------------------------------------------------------------
 *
 * passwordpolicy_auth.h
 *      Authentication checks for passwordpolicy
 *
 * Copyright (c) 2024-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */
#ifndef _PASSWORDPOLICY_AUTH_H_
#define _PASSWORDPOLICY_AUTH_H_

#include <postgres.h>
#include <libpq/libpq-be.h>

/**
 * \brief Handles client authentication and soft-lock checks
 *
 * Called after PostgreSQL authentication to check for failed login attempts
 * and enforce account soft-locking before granting access.
 *
 * \param port client connection port
 * \param status authentication status (STATUS_OK, STATUS_AUTH_OK, or STATUS_EOF)
 */
extern PGDLLEXPORT void passwordpolicy_client_authentication(Port *port, int status);

#endif
