/*
 * Copyright (C) 2015 Square, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package keywhiz.service.daos;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Throwables;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import javax.inject.Inject;
import keywhiz.api.model.SecretContent;
import keywhiz.jooq.tables.records.SecretsContentRecord;
import keywhiz.jooq.tables.records.SecretsRecord;
import keywhiz.service.config.Readonly;
import org.jooq.Configuration;
import org.jooq.DSLContext;
import org.jooq.impl.DSL;

import static com.google.common.base.Preconditions.checkNotNull;
import static keywhiz.jooq.tables.Secrets.SECRETS;
import static keywhiz.jooq.tables.SecretsContent.SECRETS_CONTENT;

/**
 * Interacts with 'secrets_content' table and actions on {@link SecretContent} entities.
 */
class SecretContentDAO {
  // Cut-off time after which we prune old, unreferenced contents
  private static final int PRUNE_CUTOFF_DAYS = 45;

  private final DSLContext dslContext;
  private final ObjectMapper mapper;
  private final SecretContentMapper secretContentMapper;

  private SecretContentDAO(DSLContext dslContext, ObjectMapper mapper,
      SecretContentMapper secretContentMapper) {
    this.dslContext = dslContext;
    this.mapper = mapper;
    this.secretContentMapper = secretContentMapper;
  }

  public long createSecretContent(long secretId, String encryptedContent,
      String creator, Map<String, String> metadata, long expiry) {
    SecretsContentRecord r = dslContext.newRecord(SECRETS_CONTENT);

    String jsonMetadata;
    try {
      jsonMetadata = mapper.writeValueAsString(metadata);
    } catch (JsonProcessingException e) {
      // Serialization of a Map<String, String> can never fail.
      throw Throwables.propagate(e);
    }

    long now = OffsetDateTime.now().toEpochSecond();

    r.setSecretid(secretId);
    r.setEncryptedContent(encryptedContent);
    r.setCreatedby(creator);
    r.setCreatedat(now);
    r.setUpdatedby(creator);
    r.setUpdatedat(now);
    r.setMetadata(jsonMetadata);
    r.setExpiry(expiry);
    r.store();

    pruneOldContents(secretId);

    return r.getId();
  }

  /**
   * Prune old secret contents from the database, for the given secret id. Whenever a new secret
   * content entry is added for a secret series, we check the database for really old content
   * entries and clean them out to prevent the database from growing too large.
   */
  @VisibleForTesting void pruneOldContents(long secretId) {
    SecretsRecord secret = dslContext.select(SECRETS.CURRENT)
        .from(SECRETS)
        .where(SECRETS.ID.eq(secretId))
        .fetchOneInto(SecretsRecord.class);

    if (secret == null || secret.getCurrent() == null) {
      // No current secret assigned, let's not prune right now.
      return;
    }

    // Remove secret contents that are older than the cutoff and are not the current version
    long cutoff = OffsetDateTime.now().minusDays(PRUNE_CUTOFF_DAYS).toEpochSecond();

    dslContext.deleteFrom(SECRETS_CONTENT)
        .where(SECRETS_CONTENT.SECRETID.eq(secretId))
        .and(SECRETS_CONTENT.CREATEDAT.lt(cutoff))
        .and(SECRETS_CONTENT.ID.ne(secret.getCurrent()))
        .execute();
  }

  public Optional<SecretContent> getSecretContentById(long id) {
    SecretsContentRecord r = dslContext.fetchOne(SECRETS_CONTENT, SECRETS_CONTENT.ID.eq(id));
    return Optional.ofNullable(r).map(secretContentMapper::map);
  }

  public static class SecretContentDAOFactory implements DAOFactory<SecretContentDAO> {
    private final DSLContext jooq;
    private final DSLContext readonlyJooq;
    private final ObjectMapper objectMapper;
    private final SecretContentMapper secretContentMapper;

    @Inject public SecretContentDAOFactory(DSLContext jooq, @Readonly DSLContext readonlyJooq,
        ObjectMapper objectMapper, SecretContentMapper secretContentMapper) {
      this.jooq = jooq;
      this.readonlyJooq = readonlyJooq;
      this.objectMapper = objectMapper;
      this.secretContentMapper = secretContentMapper;
    }

    @Override public SecretContentDAO readwrite() {
      return new SecretContentDAO(jooq, objectMapper, secretContentMapper);
    }

    @Override public SecretContentDAO readonly() {
      return new SecretContentDAO(readonlyJooq, objectMapper, secretContentMapper);
    }

    @Override public SecretContentDAO using(Configuration configuration) {
      DSLContext dslContext = DSL.using(checkNotNull(configuration));
      return new SecretContentDAO(dslContext, objectMapper, secretContentMapper);
    }
  }
}
