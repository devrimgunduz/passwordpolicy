/*-------------------------------------------------------------------------
 *
 * passwordpolicy_hash_accounts.c
 *      Hash table for Authentication Accounts
 *
 * Copyright (c) 2024-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_hash_accounts.h"

#include <access/xact.h>
#include <executor/spi.h>
#include <pgstat.h>
#include <storage/shmem.h>
#include <utils/hsearch.h>
#include <utils/snapmgr.h>

#include "passwordpolicy_vars.h"

/* Private functions forward declaration */
static void passwordpolicy_hash_accounts_add(const char *username);
static void passwordpolicy_hash_accounts_hard_delete(void);
static void passwordpolicy_hash_accounts_soft_delete(void);

/**
 * @brief init the hash table to store accounts
 */
void passwordpolicy_hash_accounts_init(void)
{
  HASHCTL info;

  info.keysize = sizeof(PasswordPolicyAccountKey);
  info.entrysize = sizeof(PasswordPolicyAccount);
#if (PG_VERSION_NUM >= 190000)
  /* PG 19 dropped the init_size argument from ShmemInitHash */
  passwordpolicy_hash_accounts = ShmemInitHash("passwordpolicy hash accounts",
                                               guc_passwordpolicy_lock_max_num_accounts,
                                               &info,
                                               HASH_ELEM | HASH_STRINGS);
#else
  passwordpolicy_hash_accounts = ShmemInitHash("passwordpolicy hash accounts",
                                               guc_passwordpolicy_lock_max_num_accounts,
                                               guc_passwordpolicy_lock_max_num_accounts,
                                               &info,
                                               HASH_ELEM | HASH_STRINGS);
#endif
}

/**
 * @brief load the existing accounts in the hash table
 */
void passwordpolicy_hash_accounts_load(void)
{
  int ret, i;
  TupleDesc tupdesc;
  SPITupleTable *tuptable;
  StringInfoData buf = {0};

  SetCurrentStatementStartTimestamp();
  StartTransactionCommand();
  SPI_connect();
  PushActiveSnapshot(GetTransactionSnapshot());

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy checking extension");

  ret = SPI_execute("SELECT 1 FROM pg_extension WHERE extname = 'passwordpolicy'", true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to check if extension is installed")));
    goto error;
  }

  if (SPI_processed == 0)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: extension is not installed, skipping account auth checks")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy soft-deleting accounts");

  /* Mark all the accounts for soft-delete */
  passwordpolicy_hash_accounts_soft_delete();

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy reading accounts");
  initStringInfo(&buf);

  if (guc_passwordpolicy_lock_all_accounts)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: reading accounts from pg_user")));
    appendStringInfo(&buf, "SELECT usename FROM pg_user ORDER BY usename");
  }
  else
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: reading accounts from passwordpolicy.accounts_lockable")));
    appendStringInfo(&buf, "SELECT usename FROM passwordpolicy.accounts_lockable ORDER BY usename");
  }

  ret = SPI_execute(buf.data, true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to get list of accounts to consider for locking")));
    goto error;
  }

  tupdesc = SPI_tuptable->tupdesc;
  tuptable = SPI_tuptable;

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy adding accounts");

  for (i = 0; i < SPI_processed; i++)
  {
    passwordpolicy_hash_accounts_add(SPI_getvalue(tuptable->vals[i], tupdesc, 1));
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy hard-deleting accounts");
  /* mark as deleted entries not present */
  passwordpolicy_hash_accounts_hard_delete();

error:
  if (buf.data)
    pfree(buf.data);
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}

/* PRIVATE FUNCTIONS */

/**
 * @brief Add an account to the hash table.
 * @param username account usename
 */
static void passwordpolicy_hash_accounts_add(const char *username)
{
  bool found;
  PasswordPolicyAccount *entry;

  if (username == NULL)
    return;

  LWLockAcquire(passwordpolicy_shm->lock_accounts, LW_EXCLUSIVE);
  entry = (PasswordPolicyAccount *)hash_search(passwordpolicy_hash_accounts, username, HASH_ENTER_NULL, &found);
  if (found)
  {
    pg_atomic_write_u64(&(entry->deleted), 0);
    LWLockRelease(passwordpolicy_shm->lock_accounts);
    ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' already in auth lock", username)));
    return;
  }

  if (entry == NULL)
  {
    LWLockRelease(passwordpolicy_shm->lock_accounts);
    ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY),
                    errmsg("passwordpolicy: not enough shared memory to add accounts to auth lock"),
                    errhint("increase the value of password_policy_lock.max_number_accounts")));
    return;
  }

  ereport(DEBUG2, (errmsg("passwordpolicy: adding account '%s' to auth lock", username)));
  pg_atomic_init_u64(&(entry->deleted), 1); /* Initialize as deleted/invalid first */
  strncpy(entry->key, username, NAMEDATALEN);
  entry->key[NAMEDATALEN] = '\0';
  pg_atomic_init_u64(&(entry->failures), 0);
  pg_atomic_init_u64(&(entry->last_failure), 0);
  pg_atomic_write_u64(&(entry->deleted), 0); /* Commit entry for readers */
  LWLockRelease(passwordpolicy_shm->lock_accounts);
}

/**
 * @brief Mark all the entries still marked for soft-deletion as deleted (1)
 */
static void passwordpolicy_hash_accounts_hard_delete(void)
{
  HASH_SEQ_STATUS hash_seq;
  PasswordPolicyAccount *entry;

  LWLockAcquire(passwordpolicy_shm->lock_accounts, LW_SHARED);
  hash_seq_init(&hash_seq, passwordpolicy_hash_accounts);
  while ((entry = (PasswordPolicyAccount *)hash_seq_search(&hash_seq)) != NULL)
  {
    if (pg_atomic_read_u64(&(entry->deleted)) == 2)
    {
      ereport(DEBUG2, (errmsg("passwordpolicy: (soft) removed account '%s' from auth lock", entry->key)));
      pg_atomic_write_u64(&(entry->deleted), 1);
    }
  }
  LWLockRelease(passwordpolicy_shm->lock_accounts);
}

/**
 * @brief Mark all the active entries as candidate to soft-deletion (2)
 */
static void passwordpolicy_hash_accounts_soft_delete(void)
{
  HASH_SEQ_STATUS hash_seq;
  PasswordPolicyAccount *entry;

  LWLockAcquire(passwordpolicy_shm->lock_accounts, LW_SHARED);
  hash_seq_init(&hash_seq, passwordpolicy_hash_accounts);
  while ((entry = (PasswordPolicyAccount *)hash_seq_search(&hash_seq)) != NULL)
  {
    if (pg_atomic_read_u64(&(entry->deleted)) == 0)
      pg_atomic_write_u64(&(entry->deleted), 2);
  }
  LWLockRelease(passwordpolicy_shm->lock_accounts);
}