/*-------------------------------------------------------------------------
 *
 * passwordpolicy_hash_history.h
 *      Hash table for Password History
 *
 * Copyright (c) 2024-2026, Francisco Miguel Biete Banon
 *
 * This code is released under the PostgreSQL licence, as given at
 *  http://www.postgresql.org/about/licence/
 *-------------------------------------------------------------------------
 */

#include "passwordpolicy_hash_history.h"

#include <access/xact.h>
#include <executor/spi.h>
#include <pgstat.h>
#include <storage/shmem.h>
#include <utils/builtins.h>
#include <utils/guc.h>
#include <utils/hsearch.h>
#include <utils/snapmgr.h>

#include "passwordpolicy_vars.h"

/* forward declaration private functions */
static void passwordpolicy_hash_history_add_internal(const char *username, const char *password_hash, const TimestampTz changed_at);

/* Public functions */

/**
 * @brief Register a password change in the account history.
 * @param username
 * @param password_hash
 * @param changed_at
 */
void passwordpolicy_hash_history_add(const char *username, const char *password_hash, const TimestampTz changed_at)
{
  LWLockAcquire(passwordpolicy_lock_history, LW_EXCLUSIVE);
  passwordpolicy_hash_history_add_internal(username, password_hash, changed_at);
  LWLockRelease(passwordpolicy_lock_history);
}

/**
 * @brief Check if a password hash exists in the user's password history
 * @param username
 * @param password_hash
 * @return true if the hash is found in history
 */
bool passwordpolicy_hash_history_exists(const char *username, const char *password_hash)
{
  bool found;
  int i;
  PasswordPolicyHistory *entry;
  bool result = false;

  if (username == NULL)
    return false;

  entry = (PasswordPolicyHistory *)hash_search(passwordpolicy_hash_history, username, HASH_FIND, &found);
  if (!found)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' without password history", username)));
    return false;
  }

  ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' with password history", username)));

  for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
  {
    if (entry->hashes[i].changed_at != 0)
    {
      if (strcmp(password_hash, entry->hashes[i].password_hash) == 0)
      {
        result = true;
        break;
      }
    }
  }

  if (!result)
    ereport(DEBUG2, (errmsg("passwordpolicy: password hash for account '%s' doesn't exist", username)));

  return result;
}

/**
 * @brief Initialize the shared hash table for password history
 */
void passwordpolicy_hash_history_init(void)
{
  HASHCTL info;

  info.keysize = sizeof(PasswordPolicyAccountKey);
  info.entrysize = offsetof(PasswordPolicyHistory, hashes) + mul_size(guc_passwordpolicy_history_max_num_entries, sizeof(PasswordPolicyHistoryHash));
  passwordpolicy_hash_history = ShmemInitHash("passwordpolicy hash history",
                                              guc_passwordpolicy_history_max_num_accounts,
                                              guc_passwordpolicy_history_max_num_accounts,
                                              &info,
                                              HASH_ELEM | HASH_STRINGS);
}

/**
 * @brief Load password history from the database table into shared memory
 */
void passwordpolicy_hash_history_load(void)
{
  bool isnull;
  char *query;
  Datum params[1];
  int ret, i;
  TimestampTz changed_at;
  TupleDesc tupdesc;
  SPIPlanPtr plan;
  SPITupleTable *tuptable;

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
    ereport(DEBUG2, (errmsg("passwordpolicy: extension is not installed, skipping password history")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy reading accounts");

  query = "WITH ranked_history AS ("
          "  SELECT usename, password_hash, changed_at, "
          "         ROW_NUMBER() OVER (PARTITION BY usename ORDER BY changed_at DESC) AS row_num "
          "  FROM passwordpolicy.accounts_password_history "
          ") "
          "SELECT usename, password_hash, changed_at "
          "FROM ranked_history "
          "WHERE row_num <= $1;";

  plan = SPI_prepare(query, 1, (Oid[]){INT4OID});
  if (plan == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history query")));
    goto error;
  }

  params[0] = Int32GetDatum(guc_passwordpolicy_history_max_num_entries);
  ret = SPI_execute_plan(plan, params, NULL, true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to read password history")));
    goto error;
  }

  tupdesc = SPI_tuptable->tupdesc;
  tuptable = SPI_tuptable;

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy loading history");

  LWLockAcquire(passwordpolicy_lock_history, LW_EXCLUSIVE);
  passwordpolicy_hash_history_last_save = 0;
  for (i = 0; i < SPI_processed; i++)
  {
    changed_at = DatumGetTimestampTz(SPI_getbinval(tuptable->vals[i], tupdesc, 3, &isnull));
    passwordpolicy_hash_history_add_internal(SPI_getvalue(tuptable->vals[i], tupdesc, 1),
                                             SPI_getvalue(tuptable->vals[i], tupdesc, 2),
                                             changed_at);
    if (changed_at > passwordpolicy_hash_history_last_save)
      passwordpolicy_hash_history_last_save = changed_at;
  }
  LWLockRelease(passwordpolicy_lock_history);

error:
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}

typedef struct HistoryUpdate
{
  char username[NAMEDATALEN];
  char hash[PG_SHA256_DIGEST_STRING_LENGTH];
  TimestampTz changed_at;
  TimestampTz oldest_change; /* For cleanup */
} HistoryUpdate;

/**
 * @brief Save the current password history from shared memory to the database table
 */
void passwordpolicy_hash_history_save(void)
{
  char *sql_delete, *sql_insert;
  Datum params_delete[2], params_insert[3];
  HASH_SEQ_STATUS hash_seq;
  int ret, i;
  PasswordPolicyHistory *entry;
  SPIPlanPtr plan_delete, plan_insert;
  TimestampTz oldest_change, newest_change;
  int max_updates;
  HistoryUpdate *updates = NULL;
  int num_updates = 0;

  SetCurrentStatementStartTimestamp();
  StartTransactionCommand();
  // SPI_connects creates a temporary memory pool, any subsequent palloc will be inside it and freed with SPI_finish
  SPI_connect();
  PushActiveSnapshot(GetTransactionSnapshot());

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy checking extension");

  if (strcmp(GetConfigOptionByName("transaction_read_only", NULL, false), "on") == 0)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: database is in read-only mode, skipping password history")));
    goto error;
  }

  ret = SPI_execute("SELECT 1 FROM pg_extension WHERE extname = 'passwordpolicy'", true, 0);
  if (ret != SPI_OK_SELECT)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to check if extension is installed")));
    goto error;
  }

  if (SPI_processed == 0)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: extension is not installed, skipping password history")));
    goto error;
  }

  pgstat_report_activity(STATE_RUNNING, "passwordpolicy delete dropped users history");
  ret = SPI_execute("DELETE FROM passwordpolicy.accounts_password_history h "
                    "WHERE NOT EXISTS (SELECT 1 FROM pg_user u WHERE u.usename = h.usename)",
                    false, 0);
  if (ret != SPI_OK_DELETE)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to delete password history for removed users")));
    goto error;
  }

  sql_delete = "DELETE FROM passwordpolicy.accounts_password_history "
               "WHERE usename = $1 AND changed_at < $2";

  plan_delete = SPI_prepare(sql_delete, 2, (Oid[]){TEXTOID, TIMESTAMPTZOID});
  if (plan_delete == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history delete")));
    goto error;
  }

  sql_insert = "INSERT INTO passwordpolicy.accounts_password_history "
               "(usename, password_hash, changed_at) "
               " VALUES ($1, $2, $3) ON CONFLICT DO NOTHING";

  plan_insert = SPI_prepare(sql_insert, 3, (Oid[]){TEXTOID, TEXTOID, TIMESTAMPTZOID});
  if (plan_insert == NULL)
  {
    ereport(ERROR, (errmsg("passwordpolicy: failed to prepare password history insert")));
    goto error;
  }

  /* Allocate memory for updates to avoid SPI inside LWLock */
  max_updates = guc_passwordpolicy_lock_max_num_accounts * guc_passwordpolicy_history_max_num_entries;
  updates = (HistoryUpdate *)palloc(sizeof(HistoryUpdate) * max_updates);

  LWLockAcquire(passwordpolicy_lock_history, LW_SHARED);
  newest_change = passwordpolicy_hash_history_last_save;
  hash_seq_init(&hash_seq, passwordpolicy_hash_history);
  while ((entry = (PasswordPolicyHistory *)hash_seq_search(&hash_seq)) != NULL)
  {
    oldest_change = 0;

    /* Find oldest change to clean up later */
    for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
    {
      if (entry->hashes[i].changed_at != 0)
      {
        if (oldest_change == 0 || oldest_change > entry->hashes[i].changed_at)
          oldest_change = entry->hashes[i].changed_at;
      }
    }

    for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
    {
      if (entry->hashes[i].changed_at != 0)
      {
        if (entry->hashes[i].changed_at > passwordpolicy_hash_history_last_save)
        {
          // only insert if it's a new history entry
          if (num_updates < max_updates)
          {
            strncpy(updates[num_updates].username, entry->key, NAMEDATALEN);
            strncpy(updates[num_updates].hash, entry->hashes[i].password_hash, PG_SHA256_DIGEST_STRING_LENGTH);
            updates[num_updates].changed_at = entry->hashes[i].changed_at;
            updates[num_updates].oldest_change = oldest_change;
            num_updates++;

            if (entry->hashes[i].changed_at > newest_change)
              newest_change = entry->hashes[i].changed_at;
          }
        }
      }
    }
  }
  LWLockRelease(passwordpolicy_lock_history);

  /* Perform SPI updates without holding LWLock */
  for (i = 0; i < num_updates; i++)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: inserting new entry for account '%s' into password history", updates[i].username)));
    pgstat_report_activity(STATE_RUNNING, "passwordpolicy insert history");

    params_insert[0] = CStringGetTextDatum(updates[i].username);
    params_insert[1] = CStringGetTextDatum(updates[i].hash);
    params_insert[2] = TimestampTzGetDatum(updates[i].changed_at);

    ret = SPI_execute_plan(plan_insert, params_insert, NULL, false, 0);
    if (ret != SPI_OK_INSERT)
    {
      ereport(ERROR, (errmsg("passwordpolicy: failed to execute password history insert")));
      goto error;
    }

    // delete only if we have a new history entry for this user
    ereport(DEBUG2, (errmsg("passwordpolicy: deleting old entries for account '%s' from password history", updates[i].username)));
    pgstat_report_activity(STATE_RUNNING, "passwordpolicy delete history");
    params_delete[0] = CStringGetTextDatum(updates[i].username);
    params_delete[1] = TimestampTzGetDatum(updates[i].oldest_change);
    ret = SPI_execute_plan(plan_delete, params_delete, NULL, false, 0);
    if (ret != SPI_OK_DELETE)
    {
      ereport(ERROR, (errmsg("passwordpolicy: failed to execute password history delete")));
      goto error;
    }
  }

  passwordpolicy_hash_history_last_save = newest_change;

error:
  SPI_finish();
  PopActiveSnapshot();
  CommitTransactionCommand();
  pgstat_report_stat(true);
  pgstat_report_activity(STATE_IDLE, NULL);
}

/* Private functions */
/* Internal function to add history, assumes lock is held */
static void passwordpolicy_hash_history_add_internal(const char *username, const char *password_hash, const TimestampTz changed_at)
{
  bool found;
  int i;
  PasswordPolicyHistory *entry;
  PasswordPolicyHistoryHash *oldest_hash;

  if (username == NULL)
    return;

  entry = (PasswordPolicyHistory *)hash_search(passwordpolicy_hash_history, username, HASH_ENTER_NULL, &found);
  if (entry == NULL)
  {
    ereport(ERROR, (errcode(ERRCODE_OUT_OF_MEMORY),
                    errmsg("passwordpolicy: not enough shared memory to add password history entry"),
                    errhint("increase the value of password_policy_history.max_number_accounts")));
    return;
  }

  if (!found)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' without password history", username)));
    strncpy(entry->key, username, NAMEDATALEN);
    entry->key[NAMEDATALEN] = '\0';
    MemSet(entry->hashes, 0, mul_size(guc_passwordpolicy_history_max_num_entries, sizeof(PasswordPolicyHistoryHash)));
  }

  oldest_hash = NULL;
  for (i = 0; i < guc_passwordpolicy_history_max_num_entries; i++)
  {
    if (entry->hashes[i].changed_at == 0)
    {
      entry->hashes[i].changed_at = changed_at;
      strcpy(entry->hashes[i].password_hash, password_hash);
      ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' password history set in '%d' '%ld'",
                              username, i, changed_at)));
      return;
    }
    else
    {
      if (oldest_hash == NULL || oldest_hash->changed_at > entry->hashes[i].changed_at)
        oldest_hash = &(entry->hashes[i]);
    }
  }

  if (oldest_hash)
  {
    ereport(DEBUG2, (errmsg("passwordpolicy: account '%s' password history overwritting '%s' '%ld'",
                            username, oldest_hash->password_hash, oldest_hash->changed_at)));
    oldest_hash->changed_at = changed_at;
    strcpy(oldest_hash->password_hash, password_hash);
  }
}
